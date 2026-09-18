#!/bin/sh

BBPROXY_URL="http://127.0.0.1:17890"

case "${1:-status}" in
    on)
        bbproxy start || return 1 2>/dev/null || exit 1
        export http_proxy="$BBPROXY_URL"
        export https_proxy="$BBPROXY_URL"
        export HTTP_PROXY="$BBPROXY_URL"
        export HTTPS_PROXY="$BBPROXY_URL"
        export no_proxy="127.0.0.1,localhost,192.168.0.0/16,172.16.0.0/12"
        export NO_PROXY="$no_proxy"
        echo "BBProxy environment enabled"
        ;;
    off)
        unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
        bbproxy stop
        echo "BBProxy environment disabled"
        ;;
    status)
        bbproxy status
        ;;
    *)
        echo "Usage: . proxy.sh on|off|status"
        ;;
esac
