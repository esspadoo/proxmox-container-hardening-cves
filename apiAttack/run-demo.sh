#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="${LAB_DIR:-$ROOT_DIR/.lab}"
QEMU_REPO="${QEMU_REPO:-https://gitlab.com/qemu-project/qemu.git}"
QEMU_VERSION="${QEMU_VERSION:-v10.2.1}"
QEMU_SRC="${QEMU_SRC:-$LAB_DIR/qemu-$QEMU_VERSION}"
PATCH_FILE="$ROOT_DIR/patches/qemu-ga-cve-2024-21545-download.patch"
TARGET_PATH="${TARGET_PATH:-/etc/cve-2024-21545-proof.txt}"

usage() {
  cat <<EOF
Usage: ./run-demo.sh [compare|e2e|smoke|requirements|fetch|patch|build|cleanup]

Modes:
  compare       Run the real vulnerable-node versus fixed-node comparison.
  e2e           Same as compare.
  smoke         Run the offline baseline/vulnerable/fixed API model.
  requirements  Check local prerequisites and print required lab settings.
  fetch         Clone the pinned QEMU source tree into .lab.
  patch         Apply the qemu-ga CVE-2024-21545 lab patch to QEMU_SRC.
  build         Apply the patch and build qemu-ga from the pinned QEMU tree.
  cleanup       Remove local .lab state.

Environment:
  TARGET_PATH=/etc/cve-2024-21545-proof.txt
                         Host proof path requested through the patched qemu-ga.
  TARGET_EXPECTED_SUBSTRING=...
                         Optional string expected in the vulnerable response.
  VULN_PVE_URL=https://pve-vuln.example:8006
  VULN_NODE=pve-vuln
  VULN_VMID=100
  FIXED_PVE_URL=https://pve-fixed.example:8006
  FIXED_NODE=pve-fixed
  FIXED_VMID=100
  PVE_API_TOKEN='user@pve!tokenid=uuid'
                         Shared API token for both nodes.
  PVE_USERNAME=lab@pve
  PVE_PASSWORD=...
                         Ticket auth fallback if no API token is set.
  PVE_INSECURE=1         Accept self-signed Proxmox lab certificates.
  QEMU_SRC=/path/to/qemu      Existing QEMU source tree for patch/build.
  QEMU_VERSION=v10.2.1        QEMU tag used by fetch/build.
  LAB_DIR=.lab                Local lab state directory.
EOF
}

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

requirements() {
  need_command python3
  echo "PASS: Python 3 is present."
  echo
  echo "Real comparison requires:"
  echo "  VULN_PVE_URL, VULN_NODE, VULN_VMID"
  echo "  FIXED_PVE_URL, FIXED_NODE, FIXED_VMID"
  echo "  PVE_API_TOKEN or PVE_USERNAME/PVE_PASSWORD"
  echo "  TARGET_PATH, default: $TARGET_PATH"
  echo
  echo "Per-node credentials can override the shared ones:"
  echo "  VULN_PVE_API_TOKEN, FIXED_PVE_API_TOKEN"
  echo "  VULN_PVE_USERNAME/VULN_PVE_PASSWORD"
  echo "  FIXED_PVE_USERNAME/FIXED_PVE_PASSWORD"
  echo
  echo "Optional build prerequisites: git, make, a C compiler, pkg-config, GLib development headers, pixman development headers, flex, and bison."
}

compare() {
  need_command python3
  LAB_DIR="$LAB_DIR" TARGET_PATH="$TARGET_PATH" \
    python3 "$ROOT_DIR/scripts/proxmox_e2e_compare.py" \
      --lab-dir "$LAB_DIR" \
      --target-path "$TARGET_PATH"
}

smoke() {
  need_command python3
  python3 "$ROOT_DIR/scripts/proxmox_api_download_lab.py" \
    --lab-dir "$LAB_DIR" \
    --path "$TARGET_PATH"
}

fetch_qemu() {
  need_command git
  mkdir -p "$LAB_DIR"

  if [ -d "$QEMU_SRC/.git" ]; then
    echo "[fetch] Updating existing QEMU tree: $QEMU_SRC"
    git -C "$QEMU_SRC" fetch --tags origin "$QEMU_VERSION"
    git -C "$QEMU_SRC" checkout --detach "$QEMU_VERSION"
    return 0
  fi

  echo "[fetch] Cloning QEMU $QEMU_VERSION into $QEMU_SRC"
  git clone --depth 1 --branch "$QEMU_VERSION" "$QEMU_REPO" "$QEMU_SRC"
}

ensure_qemu_src() {
  if [ ! -f "$QEMU_SRC/qga/main.c" ]; then
    echo "QEMU source tree not found at $QEMU_SRC." >&2
    echo "Run './run-demo.sh fetch' or set QEMU_SRC=/path/to/qemu." >&2
    exit 1
  fi
}

patch_status() {
  ensure_qemu_src

  if git -C "$QEMU_SRC" apply --check "$PATCH_FILE" >/dev/null 2>&1; then
    echo "not-applied"
    return 0
  fi

  if git -C "$QEMU_SRC" apply --reverse --check "$PATCH_FILE" >/dev/null 2>&1; then
    echo "already-applied"
    return 0
  fi

  echo "conflict"
}

apply_qemu_patch() {
  need_command git
  ensure_qemu_src

  case "$(patch_status)" in
    not-applied)
      echo "[patch] Applying $PATCH_FILE"
      git -C "$QEMU_SRC" apply "$PATCH_FILE"
      ;;
    already-applied)
      echo "[patch] Patch is already applied."
      ;;
    *)
      echo "Patch does not apply cleanly to $QEMU_SRC." >&2
      echo "Use QEMU $QEMU_VERSION or review local changes in qga/main.c." >&2
      exit 1
      ;;
  esac
}

build_qemu_ga() {
  need_command git
  need_command make

  if [ ! -f "$QEMU_SRC/qga/main.c" ]; then
    fetch_qemu
  fi

  apply_qemu_patch

  echo "[build] Configuring QEMU guest-agent build."
  (
    cd "$QEMU_SRC"
    ./configure --enable-guest-agent --disable-werror
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" qemu-ga
  )

  echo "Built patched guest agent:"
  echo "  $QEMU_SRC/build/qga/qemu-ga"
}

cleanup() {
  case "$LAB_DIR" in
    "$ROOT_DIR/.lab"|"$ROOT_DIR/.lab"/*)
      rm -rf "$LAB_DIR"
      echo "Removed $LAB_DIR"
      ;;
    *)
      echo "Refusing to remove LAB_DIR outside $ROOT_DIR/.lab: $LAB_DIR" >&2
      exit 1
      ;;
  esac
}

main() {
  local mode="${1:-compare}"

  case "$mode" in
    compare|e2e)
      compare
      ;;
    smoke)
      smoke
      ;;
    requirements)
      requirements
      ;;
    fetch)
      fetch_qemu
      ;;
    patch)
      apply_qemu_patch
      ;;
    build)
      build_qemu_ga
      ;;
    cleanup)
      cleanup
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
