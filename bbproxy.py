#!/usr/bin/env python3
"""BBProxy: a tiny local HTTP proxy to TLS HTTP-proxy bridge for BB10/QNX."""

import argparse
import base64
import getpass
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

APP_DIR = os.path.join(os.path.expanduser("~"), ".bbproxy")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
PID_FILE = os.path.join(APP_DIR, "bbproxy.pid")
LOG_FILE = os.path.join(APP_DIR, "bbproxy.log")
DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 17890


def ensure_dir():
    os.makedirs(APP_DIR, mode=0o700, exist_ok=True)


def load_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    nodes = data.get("nodes", [])
    active = int(data.get("active", 0))
    if not nodes or active < 0 or active >= len(nodes):
        raise RuntimeError("No active proxy node. Run: bbproxy configure")
    return data, nodes[active]


def save_config(data):
    ensure_dir()
    temp = CONFIG_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    os.chmod(temp, 0o600)
    os.replace(temp, CONFIG_FILE)


def split_fields(text):
    fields, current, quote, depth = [], [], None, 0
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
            current.append(char)
        elif char in "[{":
            depth += 1
            current.append(char)
        elif char in "]}":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        fields.append("".join(current).strip())
    return fields


def scalar(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    lower = value.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def parse_mapping(text):
    result = {}
    for item in split_fields(text.strip().strip("{}")):
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        result[key.strip()] = scalar(value)
    return result


def parse_clash_http_nodes(text):
    nodes, current, in_proxies = [], None, False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "proxies:":
            in_proxies = True
            continue
        if in_proxies and not line.startswith((" ", "\t", "-")):
            break
        if not in_proxies:
            continue
        if stripped.startswith("- {"):
            if current and str(current.get("type", "")).lower() == "http":
                nodes.append(current)
            node = parse_mapping(stripped[1:].strip())
            if str(node.get("type", "")).lower() == "http":
                nodes.append(node)
            current = None
        elif stripped.startswith("- "):
            if current and str(current.get("type", "")).lower() == "http":
                nodes.append(current)
            current = parse_mapping(stripped[2:])
        elif current is not None and ":" in stripped:
            key, value = stripped.split(":", 1)
            current[key.strip()] = scalar(value)
    if current and str(current.get("type", "")).lower() == "http":
        nodes.append(current)
    clean = []
    for node in nodes:
        if node.get("server") and node.get("port"):
            clean.append({
                "name": str(node.get("name", node["server"])),
                "server": str(node["server"]),
                "port": int(node["port"]),
                "username": str(node.get("username", "")),
                "password": str(node.get("password", "")),
                "tls": bool(node.get("tls", False)),
                "verify": False,
            })
    return clean


def read_header(stream, limit=65536):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = stream.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise RuntimeError("HTTP header too large")
    return bytes(data)


def upstream_socket(node):
    raw = socket.create_connection((node["server"], int(node["port"])), timeout=30)
    if not node.get("tls", False):
        return raw
    context = ssl._create_unverified_context()
    return context.wrap_socket(raw, server_hostname=node["server"])


def auth_header(node):
    user = node.get("username", "")
    password = node.get("password", "")
    if not user and not password:
        return b""
    token = base64.b64encode((user + ":" + password).encode("utf-8"))
    return b"Proxy-Authorization: Basic " + token + b"\r\n"


def tunnel(left, right):
    sockets = [left, right]
    for sock in sockets:
        sock.settimeout(None)
    while True:
        readable, _, _ = select.select(sockets, [], [], 60)
        if not readable:
            continue
        for source in readable:
            data = source.recv(32768)
            if not data:
                return
            target = right if source is left else left
            target.sendall(data)


def add_proxy_auth(header, node):
    head, separator, body = header.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    lines = [line for line in lines if not line.lower().startswith(b"proxy-authorization:")]
    auth = auth_header(node).rstrip(b"\r\n")
    if auth:
        lines.append(auth)
    return b"\r\n".join(lines) + separator + body


AGENT_PREFIX = "/agent_request/"


def request_path(raw):
    text = raw.decode("latin1", "replace")
    if text.startswith("http://") or text.startswith("https://"):
        rest = text.split("://", 1)[1]
        slash = rest.find("/")
        text = rest[slash:] if slash >= 0 else "/"
    return text


def parse_agent_request(raw_target):
    text = request_path(raw_target)
    if not text.startswith(AGENT_PREFIX):
        return None
    rest = text[len(AGENT_PREFIX):]
    parts = rest.split("/", 2)
    if len(parts) < 2 or parts[0] not in ("http", "https") or not parts[1]:
        return None
    scheme = parts[0]
    hostport = parts[1]
    path = "/" + parts[2] if len(parts) > 2 else "/"
    if hostport.startswith("[") and "]" in hostport:
        end = hostport.find("]")
        hostname = hostport[1:end]
        extra = hostport[end + 1:]
        port_s = extra[1:] if extra.startswith(":") else ""
    elif hostport.count(":") == 1:
        hostname, port_s = hostport.rsplit(":", 1)
    else:
        hostname, port_s = hostport, ""
    if not hostname:
        return None
    if port_s:
        try:
            port = int(port_s)
        except ValueError:
            return None
    else:
        port = 443 if scheme == "https" else 80
    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
    }


def origin_host(info):
    default = 443 if info["scheme"] == "https" else 80
    if info["port"] == default:
        return info["hostname"]
    return "%s:%d" % (info["hostname"], info["port"])


def rewrite_origin_request(request, method, path, host):
    head, separator, body = request.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    version = b"HTTP/1.1"
    first = lines[0].split()
    if len(first) >= 3:
        version = first[2]
    hop = (b"host:", b"proxy-authorization:", b"proxy-connection:", b"connection:")
    path_b = path.encode("latin1") if not isinstance(path, bytes) else path
    out = [method + b" " + path_b + b" " + version]
    for line in lines[1:]:
        lower = line.lower()
        skip = False
        for prefix in hop:
            if lower.startswith(prefix):
                skip = True
                break
        if skip:
            continue
        out.append(line)
    out.append(b"Host: " + host.encode("ascii", "replace"))
    out.append(b"Connection: close")
    return b"\r\n".join(out) + separator + body


def connect_via_proxy(node, hostname, port):
    upstream = upstream_socket(node)
    target = ("%s:%d" % (hostname, port)).encode("ascii")
    message = (
        b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n"
        + auth_header(node) + b"Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    try:
        upstream.sendall(message)
        response = read_header(upstream)
        status = response.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            raise RuntimeError("CONNECT %s failed: %s" % (
                target.decode("ascii"), status.decode("ascii", "replace")))
        leftover = b""
        if b"\r\n\r\n" in response:
            leftover = response.split(b"\r\n\r\n", 1)[1]
        return upstream, leftover
    except Exception:
        try:
            upstream.close()
        except Exception:
            pass
        raise


def http_complete(buf):
    if b"\r\n\r\n" not in buf:
        return False
    head, body = buf.split(b"\r\n\r\n", 1)
    cl = None
    chunked = False
    for line in head.split(b"\r\n")[1:]:
        low = line.lower()
        if low.startswith(b"content-length:"):
            try:
                cl = int(low.split(b":", 1)[1].strip())
            except ValueError:
                cl = None
        if low.startswith(b"transfer-encoding:") and b"chunked" in low:
            chunked = True
    if chunked:
        return body.endswith(b"0\r\n\r\n") or b"\r\n0\r\n\r\n" in body
    if cl is not None:
        return len(body) >= cl
    return False


def tls_http_exchange(sock, hostname, request, leftover=b"", timeout=20):
    # Clash 上游已是 TLS。不能再 wrap_socket(同一 fd)，否则会绕过外层 TLS。
    context = ssl._create_unverified_context()
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    obj = context.wrap_bio(incoming, outgoing, server_hostname=hostname)
    deadline = time.time() + timeout
    if leftover:
        incoming.write(leftover)

    def remaining():
        left = deadline - time.time()
        if left <= 0:
            raise socket.timeout("agent TLS timed out")
        return left

    def flush():
        data = outgoing.read()
        if data:
            sock.settimeout(remaining())
            sock.sendall(data)

    def pull():
        sock.settimeout(remaining())
        data = sock.recv(32768)
        if not data:
            raise RuntimeError("proxy tunnel closed")
        incoming.write(data)

    while True:
        try:
            obj.do_handshake()
            flush()
            break
        except ssl.SSLWantReadError:
            flush()
            pull()
        except ssl.SSLWantWriteError:
            flush()

    offset = 0
    while offset < len(request):
        try:
            n = obj.write(request[offset:])
            if n:
                offset += n
            flush()
        except ssl.SSLWantReadError:
            flush()
            pull()
        except ssl.SSLWantWriteError:
            flush()

    buf = b""
    while True:
        try:
            data = obj.read(32768)
            if not data:
                return buf
            buf += data
            if http_complete(buf):
                return buf
        except ssl.SSLWantReadError:
            flush()
            pull()
        except ssl.SSLWantWriteError:
            flush()


def handle_agent_request(client, request, method, info, node, logger):
    host = origin_host(info)
    verb = method.decode("ascii", "replace")
    logger("AGENT start %s %s://%s%s" % (verb, info["scheme"], host, info["path"]))
    if info["scheme"] == "https":
        raw, leftover = connect_via_proxy(node, info["hostname"], info["port"])
        rewritten = rewrite_origin_request(request, method, info["path"], host)
        try:
            logger("AGENT connect-ok %s" % host)
            response = tls_http_exchange(raw, info["hostname"], rewritten, leftover)
            logger("AGENT https %s %s %s bytes=%s" % (verb, host, info["path"], len(response)))
            if response:
                client.sendall(response)
        finally:
            try:
                raw.close()
            except Exception:
                pass
        return
    abs_url = "http://%s%s" % (host, info["path"])
    rewritten = rewrite_origin_request(request, method, abs_url, host)
    upstream = upstream_socket(node)
    logger("AGENT http %s %s" % (verb, abs_url))
    try:
        upstream.sendall(add_proxy_auth(rewritten, node))
        tunnel(client, upstream)
    finally:
        try:
            upstream.close()
        except Exception:
            pass


def handle_client(client, address, node, logger):
    upstream = None
    try:
        request = read_header(client)
        if not request:
            return
        first = request.split(b"\r\n", 1)[0]
        parts = first.split()
        if len(parts) < 3:
            raise RuntimeError("Invalid HTTP request")
        method = parts[0].upper()
        agent = parse_agent_request(parts[1])
        if agent:
            handle_agent_request(client, request, method, agent, node, logger)
            return
        upstream = upstream_socket(node)
        if method == b"CONNECT":
            target = parts[1].decode("ascii", "replace")
            message = (
                b"CONNECT " + parts[1] + b" HTTP/1.1\r\nHost: " + parts[1] + b"\r\n"
                + auth_header(node) + b"Proxy-Connection: Keep-Alive\r\n\r\n"
            )
            upstream.sendall(message)
            response = read_header(upstream)
            client.sendall(response)
            status = response.split(b"\r\n", 1)[0]
            logger("CONNECT %s -> %s" % (target, status.decode("ascii", "replace")))
            if b" 200 " not in status:
                return
            tunnel(client, upstream)
        else:
            upstream.sendall(add_proxy_auth(request, node))
            logger("HTTP %s" % first.decode("latin1", "replace"))
            tunnel(client, upstream)
    except Exception as exc:
        logger("client %s error: %s" % (address[0], exc))
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
    finally:
        try:
            client.close()
        except Exception:
            pass
        if upstream:
            try:
                upstream.close()
            except Exception:
                pass


def serve():
    ensure_dir()
    config, node = load_config()
    listen = config.get("listen", DEFAULT_LISTEN)
    port = int(config.get("port", DEFAULT_PORT))
    stop = threading.Event()

    def logger(message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write("%s %s\n" % (stamp, message))

    def on_signal(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen, port))
    server.listen(32)
    server.settimeout(1)
    with open(PID_FILE, "w", encoding="ascii") as handle:
        handle.write(str(os.getpid()))
    logger("started on %s:%d via %s:%s tls=%s" % (
        listen, port, node["server"], node["port"], node.get("tls", False)))
    try:
        while not stop.is_set():
            try:
                client, address = server.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(target=handle_client, args=(client, address, node, logger))
            thread.daemon = True
            thread.start()
    finally:
        server.close()
        try:
            os.unlink(PID_FILE)
        except OSError:
            pass
        logger("stopped")


def listener_up():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.3)
    try:
        probe.connect((DEFAULT_LISTEN, DEFAULT_PORT))
        return True
    except Exception:
        return False
    finally:
        probe.close()


def running_pid():
    try:
        with open(PID_FILE, "r", encoding="ascii") as handle:
            pid = int(handle.read().strip())
        # QNX can reject kill(pid, 0) even for a live process in another
        # application context. /proc is the reliable liveness check here.
        if os.path.exists("/proc/%d" % pid):
            return pid
        try:
            os.kill(pid, 0)
            return pid
        except OSError:
            if listener_up():
                return pid
    except (OSError, ValueError):
        return None
    return None


def command_start(_args):
    load_config()
    pid = running_pid()
    if pid:
        print("BBProxy is already running (pid %d)" % pid)
        return
    if listener_up():
        print("BBProxy is already running")
        return
    ensure_dir()
    log = open(LOG_FILE, "a", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "serve"],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log.close()
    for _ in range(50):
        time.sleep(0.3)
        if running_pid() or listener_up():
            print("BBProxy started on http://127.0.0.1:%d" % DEFAULT_PORT)
            return
        if process.poll() is not None:
            break
    if running_pid() or listener_up():
        print("BBProxy started on http://127.0.0.1:%d" % DEFAULT_PORT)
        return
    raise RuntimeError("BBProxy failed to start. Check %s" % LOG_FILE)


def command_stop(_args):
    pid = running_pid()
    if not pid:
        print("BBProxy is not running")
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        time.sleep(0.1)
        if not running_pid():
            print("BBProxy stopped")
            return
    print("Stop requested for pid %d" % pid)


def command_status(_args):
    pid = running_pid()
    if not os.path.exists(CONFIG_FILE):
        print("BBProxy is not configured")
        return
    config, node = load_config()
    print("Status : %s" % ("running (pid %d)" % pid if pid else "stopped"))
    print("Listen : http://%s:%s" % (config.get("listen", DEFAULT_LISTEN), config.get("port", DEFAULT_PORT)))
    print("Node   : %s" % node.get("name", node["server"]))
    print("Server : %s:%s" % (node["server"], node["port"]))
    print("TLS    : %s" % ("yes" if node.get("tls") else "no"))


def command_configure(args):
    password = args.password
    if password is None:
        password = getpass.getpass("Proxy password: ")
    node = {
        "name": args.name or args.server,
        "server": args.server,
        "port": args.server_port,
        "username": args.username or "",
        "password": password or "",
        "tls": args.tls,
        "verify": not args.insecure,
    }
    save_config({"listen": DEFAULT_LISTEN, "port": DEFAULT_PORT, "active": 0, "nodes": [node]})
    print("Saved node: %s" % node["name"])


def urlopen_skip_verify(request, timeout=60):
    context = ssl._create_unverified_context()
    return urllib.request.urlopen(request, timeout=timeout, context=context)


def command_import(args):
    request = urllib.request.Request(args.url, headers={"User-Agent": "BBProxy/0.1"})
    with urlopen_skip_verify(request, timeout=60) as response:
        content = response.read().decode("utf-8-sig")
    nodes = parse_clash_http_nodes(content)
    if not nodes:
        raise RuntimeError("No HTTP proxy nodes found in Clash subscription")
    save_config({"listen": DEFAULT_LISTEN, "port": DEFAULT_PORT, "active": 0, "nodes": nodes})
    print("Imported %d HTTP proxy node(s)" % len(nodes))
    for index, node in enumerate(nodes, 1):
        print("%d) %s" % (index, node["name"]))


def command_nodes(_args):
    config, _node = load_config()
    active = int(config.get("active", 0))
    for index, node in enumerate(config["nodes"]):
        print("%s%d) %s" % ("* " if index == active else "  ", index + 1, node["name"]))


def command_use(args):
    config, _node = load_config()
    index = args.index - 1
    if index < 0 or index >= len(config["nodes"]):
        raise RuntimeError("Node index out of range")
    config["active"] = index
    save_config(config)
    print("Selected node: %s" % config["nodes"][index]["name"])
    if running_pid():
        command_stop(args)
        command_start(args)


def main():
    parser = argparse.ArgumentParser(prog="bbproxy")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("start").set_defaults(func=command_start)
    sub.add_parser("stop").set_defaults(func=command_stop)
    sub.add_parser("restart").set_defaults(func=lambda args: (command_stop(args), command_start(args)))
    sub.add_parser("status").set_defaults(func=command_status)
    sub.add_parser("nodes").set_defaults(func=command_nodes)
    use = sub.add_parser("use")
    use.add_argument("index", type=int)
    use.set_defaults(func=command_use)
    configure = sub.add_parser("configure")
    configure.add_argument("--name")
    configure.add_argument("--server", required=True)
    configure.add_argument("--port", dest="server_port", type=int, required=True)
    configure.add_argument("--username", default="")
    configure.add_argument("--password")
    configure.add_argument("--tls", action="store_true")
    configure.add_argument("--insecure", action="store_true")
    configure.set_defaults(func=command_configure)
    importer = sub.add_parser("import")
    importer.add_argument("url")
    importer.set_defaults(func=command_import)
    sub.add_parser("serve").set_defaults(func=lambda _args: serve())
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
