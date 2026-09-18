#!/bin/sh
set -eu

DEST="/accounts/1000/shared/misc/bbproxy"
mkdir -p "$DEST"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$SOURCE_DIR" != "$DEST" ]; then
    cp "$SOURCE_DIR/bbproxy.py" "$SOURCE_DIR/proxy.sh" "$SOURCE_DIR/bbproxy" "$DEST/"
fi
chmod 700 "$DEST/bbproxy.py" "$DEST/proxy.sh" "$DEST/bbproxy"

BIN_DIR="${NATIVE_TOOLS:-/accounts/1000/shared/misc/berrycore}/bin"
mkdir -p "$BIN_DIR"
rm -f "$BIN_DIR/bbproxy"
cp "$DEST/bbproxy" "$BIN_DIR/bbproxy"
chmod 700 "$BIN_DIR/bbproxy"

echo "BBProxy installed"
echo "Configure: bbproxy configure --server HOST --port 443 --username USER --tls"
echo "Enable:    . $DEST/proxy.sh on"
