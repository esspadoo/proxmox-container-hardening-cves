# CNS code examples

Small, isolated demos for container, host confinement, and vulnerability
analysis labs. Each demo keeps its own README with requirements, run steps,
expected results, cleanup, and references.

## Demos

- [AppArmor docviewd host demo](apparmor-docview-demo/README.md)
- [AppArmor Nginx container demo](apparmor-nginx-container-demo/README.md)
- [Proxmox VE CVE-2024-21545 API demo](proxmox-cve-2024-21545-api-demo/README.md)
- [Redis CVE-2022-0543 AppArmor container demo](redis-cve-2022-0543-demo/README.md)
- [runc CVE-2024-21626 AppArmor demo](runc-cve-2024-21626-demo/README.md)
- [ABRT CVE-2025-12744 SELinux demo](abrt-cve-2025-12744-selinux-demo/README.md)

## Use

Open the README for the demo you want to run and follow its lab-specific
instructions. Most demos require a Linux VM with AppArmor, SELinux, Docker, or
the vulnerable software version described in that demo.

Run these only in disposable lab environments.
