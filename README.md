# BBProxy

BBProxy 是为 BlackBerry 10 / BerryCore 编写的零第三方依赖 Python 3 代理桥。它只监听本机 `127.0.0.1:17890`，连接 Clash 订阅中的 HTTP 代理节点，并支持节点本身使用 TLS（`type: http, tls: true`）。

它提供两种使用方式：

- Shell 标准代理：让 `wget`、Python 等程序通过 `http_proxy` / `https_proxy` 使用 BBProxy。
- LAI 请求网关：让不能自行发送 HTTP `CONNECT` 的 BB10 WebView 通过 `/agent_request/` 访问 HTTP(S) API。

## 文件与运行环境

默认安装目录：

```text
/accounts/1000/shared/misc/bbproxy
```

运行数据保存在当前 Term49 用户目录：

```text
~/.bbproxy/config.json   # 节点配置，权限 0600
~/.bbproxy/bbproxy.pid  # 进程号
~/.bbproxy/bbproxy.log  # 运行日志
```

需要 BerryCore 提供 Python 3。服务由 Term49 的 `blackberry` 用户启动，不是 BB10 的系统级全局代理。

## 安装

在项目目录执行：

```sh
sh ./install.sh
```

脚本把运行文件复制到 `/accounts/1000/shared/misc/bbproxy`，并把 `bbproxy` 命令安装到 `${NATIVE_TOOLS:-/accounts/1000/shared/misc/berrycore}/bin`。

## 配置单个节点

```sh
bbproxy configure \
  --name "Japan 4" \
  --server proxy.example.com \
  --port 443 \
  --username USER \
  --tls
```

未提供 `--password` 时会安全提示输入，密码不会回显。`--tls` 表示 BBProxy 到上游 HTTP 代理之间使用 TLS。

## 导入 Clash 订阅

```sh
bbproxy import 'CLASH_SUBSCRIPTION_URL'
bbproxy nodes
bbproxy use 2
```

只导入 `type: http` 节点，支持普通块状和行内 Clash YAML；`ss`、`vmess`、`trojan` 等节点不会导入。`use N` 切换节点；服务正在运行时会自动重启。

## 服务管理

```sh
bbproxy start
bbproxy status
bbproxy restart
bbproxy stop
```

服务地址固定为：

```text
http://127.0.0.1:17890
```

启动和状态检查会同时核对 PID 与监听端口，以适应 QNX 应用沙箱无法对其他上下文执行 `kill(pid, 0)` 的情况。发生错误时查看：

```sh
cat ~/.bbproxy/bbproxy.log
```

## 在当前 Term49 Shell 中启用

启用：

```sh
. /accounts/1000/shared/misc/bbproxy/proxy.sh on
```

关闭：

```sh
. /accounts/1000/shared/misc/bbproxy/proxy.sh off
```

开头的 `.` 表示在当前 Shell 中执行脚本，这样脚本设置的环境变量才会保留。启用后会设置大小写两套 `http_proxy` / `https_proxy`，并设置：

```text
no_proxy=127.0.0.1,localhost,192.168.0.0/16,172.16.0.0/12
```

这些变量只影响当前 Shell 以及从它启动的子进程，不会自动改变其他 BB10 应用的网络。

## LAI `/agent_request/` 网关

BB10 WebView 无法像完整代理客户端一样对 HTTPS 代理发送 `CONNECT`。LAI 可把真实目标编码进本地 URL：

```text
真实目标：
https://openapi.okx.com/api/v5/account/balance

发给 BBProxy：
http://127.0.0.1:17890/agent_request/https/openapi.okx.com/api/v5/account/balance
```

通用格式：

```text
http://127.0.0.1:17890/agent_request/<http|https>/<host>[:port]/<path>?<query>
```

对 HTTPS 目标，BBProxy 会先通过选定的上游节点建立 `CONNECT` 隧道，再在隧道内与目标站点完成 TLS，并返回原始 HTTP 响应。请求方法、正文和业务请求头会保留；`Host`、代理认证和连接类头由 BBProxy 重写。

涉及签名的 API（例如 OKX）仍应按照真实目标路径 `/api/v5/...` 计算签名，不能把 `/agent_request/...` 前缀加入签名。

## TLS 与安全限制

为兼容 BB10 过期或不完整的 CA 证书库，当前设备版本会跳过以下 TLS 证书验证：

- 下载 Clash 订阅；
- 连接启用 TLS 的上游 HTTP 代理；
- `/agent_request/https/...` 网关连接目标 HTTPS 站点。

这能避免常见的 `CERTIFICATE_VERIFY_FAILED`，但也降低了对中间人攻击的防护。只应使用可信订阅与代理节点，且 BBProxy 必须保持监听在 `127.0.0.1`，不要暴露到局域网或公网。

## 常见问题

- `Failed reading proxy response` / `Proxy tunneling failed`：通常是节点不支持 HTTP 代理、节点失效或服务端主动断开；用 `bbproxy nodes` 和 `bbproxy use N` 更换节点。
- `BBProxy failed to start`：先运行 `bbproxy status`，再查看 `~/.bbproxy/bbproxy.log`；QNX 有时无法直接检查另一应用上下文中的 PID，但端口可能已经正常监听。
- 局域网地址也走了代理：确认使用 `. proxy.sh on`，并检查当前 Shell 的 `no_proxy`。
- 关闭 Term49 窗口不等于停止 BBProxy；需要显式运行 `bbproxy stop` 或 `. proxy.sh off`。
