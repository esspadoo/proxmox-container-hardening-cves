#!/usr/bin/env bash
set -euo pipefail

PROFILE_NAME="${PROFILE_NAME:-corp-nginx-web}"
PROFILE_FILE="${PROFILE_FILE:-/etc/apparmor.d/containers/corp-nginx-web}"
IMAGE="${IMAGE:-nginx:1.27-alpine}"
CONTAINER="${CONTAINER:-edge-nginx}"
HOST_PORT="${HOST_PORT:-8080}"
HOST_ROOT="${HOST_ROOT:-/srv/nginx}"

stop_container() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

if ! sudo -v; then
  echo "sudo is required to install /srv/nginx files and load the AppArmor profile." >&2
  exit 1
fi

echo "[1/6] Installing Nginx configuration and static content..."
sudo install -d -m 0755 "$HOST_ROOT/conf.d" "$HOST_ROOT/html"
sudo install -m 0644 nginx/nginx.conf "$HOST_ROOT/nginx.conf"
sudo install -m 0644 nginx/conf.d/default.conf "$HOST_ROOT/conf.d/default.conf"
sudo install -m 0644 html/index.html "$HOST_ROOT/html/index.html"

echo "[2/6] Loading AppArmor profile..."
sudo install -d -m 0755 "$(dirname "$PROFILE_FILE")"
sudo install -m 0644 apparmor/corp-nginx-web "$PROFILE_FILE"
sudo apparmor_parser -r -W "$PROFILE_FILE"

echo "[3/6] Ensuring image is available..."
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

echo "[4/6] Starting hardened Nginx container..."
stop_container
docker run -d --name "$CONTAINER" \
  --entrypoint /usr/sbin/nginx \
  --read-only \
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --mount type=bind,src="$HOST_ROOT/nginx.conf",dst=/etc/nginx/nginx.conf,ro \
  --mount type=bind,src="$HOST_ROOT/conf.d",dst=/etc/nginx/conf.d,ro \
  --mount type=bind,src="$HOST_ROOT/html",dst=/usr/share/nginx/html,ro \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --cap-add CHOWN \
  --security-opt apparmor="$PROFILE_NAME" \
  --security-opt no-new-privileges=true \
  -p "$HOST_PORT:80" \
  "$IMAGE" -g 'daemon off;'

echo "[5/6] Checking service and profile label..."
sleep 1
curl -fsS "http://127.0.0.1:$HOST_PORT/" >/dev/null
pid="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"
sudo cat "/proc/$pid/attr/current"

echo "[6/6] Checking expected denials..."
if docker exec "$CONTAINER" /bin/sh -c 'true' >/tmp/nginx-shell.out 2>&1; then
  echo "FAIL: /bin/sh executed unexpectedly"
  exit 1
fi
cat /tmp/nginx-shell.out

if docker exec "$CONTAINER" /usr/bin/env >/tmp/nginx-env.out 2>&1; then
  echo "FAIL: /usr/bin/env executed unexpectedly"
  exit 1
fi
cat /tmp/nginx-env.out

echo "PASS: service responds and generic helper execution is denied."
echo "Logs:"
echo "  sudo journalctl -k --since '10 minutes ago' | grep -Ei 'apparmor=.*(DENIED|ALLOWED).*corp-nginx-web|corp-nginx-web.*apparmor='"
echo "Cleanup:"
echo "  docker rm -f $CONTAINER"
