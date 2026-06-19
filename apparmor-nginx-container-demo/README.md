# AppArmor Nginx container demo

This demo runs the official `nginx:1.27-alpine` image with a custom AppArmor
profile, a read-only root filesystem, read-only bind mounts for configuration
and content, and small tmpfs mounts for runtime state.

## Requirements

Use an AppArmor-enabled Linux host with Docker:

```bash
sudo apt install -y apparmor apparmor-utils docker.io curl
sudo systemctl enable --now apparmor docker
```

The Docker daemon must report AppArmor in its security options:

```bash
docker info --format '{{.SecurityOptions}}'
```

## Run

```bash
./run-demo.sh
```

By default the container is published on `127.0.0.1:8080` through Docker's
normal port publishing. The service listens on port 80 inside the container.

## Expected checks

The script verifies that:

- the HTTP service responds;
- the container root process is labeled `corp-nginx-web (enforce)`;
- `/bin/sh` and `/usr/bin/env` cannot be executed inside the container.

The host files installed under `/srv/nginx` are intentionally readable by the
container, but configuration and document-root writes are outside the AppArmor
profile.

## Cleanup

```bash
docker rm -f edge-nginx
sudo apparmor_parser -R /etc/apparmor.d/containers/corp-nginx-web
```
