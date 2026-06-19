#!/usr/bin/env bash
set -euo pipefail

PROFILE_FILE="${PROFILE_FILE:-/etc/apparmor.d/usr.local.bin.docviewd}"
BINARY="${BINARY:-/usr/local/bin/docviewd}"
USER_NAME="${USER_NAME:-docview}"
BUILD_DIR="${BUILD_DIR:-build}"

stop_docviewd() {
  if ! pgrep -x docviewd >/dev/null 2>&1; then
    return 0
  fi

  sudo pkill -TERM -x docviewd >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! pgrep -x docviewd >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  sudo pkill -KILL -x docviewd >/dev/null 2>&1 || true
}

echo "[1/6] Building docviewd..."
if ! mkdir -p "$BUILD_DIR" 2>/dev/null || [ ! -w "$BUILD_DIR" ]; then
  BUILD_DIR="$(mktemp -d /tmp/docviewd-build.XXXXXX)"
fi
gcc -O2 -Wall -Wextra -o "$BUILD_DIR/docviewd" src/docviewd.c

echo "[2/6] Installing host binary and demo files..."
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  sudo useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi

sudo install -m 0755 "$BUILD_DIR/docviewd" "$BINARY"
sudo install -d -m 0755 /srv/docview/public
sudo install -m 0644 public/index.html /srv/docview/public/index.html
sudo install -m 0644 secret.txt /srv/docview/secret.txt
sudo install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 /var/log/docviewd /run/docviewd
sudo install -o "$USER_NAME" -g "$USER_NAME" -m 0644 /dev/null /var/log/docviewd/access.log

echo "[3/6] Loading AppArmor profile in complain mode..."
sudo install -m 0644 apparmor/usr.local.bin.docviewd "$PROFILE_FILE"
sudo apparmor_parser -r -C -W "$PROFILE_FILE"

echo "[4/6] Stopping any previous docviewd process..."
stop_docviewd

echo "[5/6] Starting docviewd as $USER_NAME on 127.0.0.1:8080..."
sudo -u "$USER_NAME" env DOCVIEW_BIND=127.0.0.1 "$BINARY" &

echo "[6/6] Basic checks..."
sleep 1
curl -fsS http://127.0.0.1:8080/status || true
echo
echo "Try:"
echo "  curl -i http://127.0.0.1:8080/"
echo "  curl -i http://127.0.0.1:8080/status"
echo "  curl -i http://127.0.0.1:8080/forbidden-read"
echo "  curl -i http://127.0.0.1:8080/forbidden-write"
echo "  curl -i http://127.0.0.1:8080/forbidden-exec"
echo
echo "Logs:"
echo "  sudo journalctl -k --since '10 minutes ago' | grep -i 'apparmor.*docviewd-demo'"
echo
echo "Switch to enforce:"
echo "  sudo aa-enforce /etc/apparmor.d/usr.local.bin.docviewd"
echo "  sudo pkill -TERM -x docviewd"
echo "  while pgrep -x docviewd >/dev/null; do sleep 0.2; done"
echo "  sudo -u $USER_NAME env DOCVIEW_BIND=127.0.0.1 $BINARY &"
echo
echo "Direct allow/deny self-test after enforce:"
echo "  sudo -u $USER_NAME $BINARY --self-test"
