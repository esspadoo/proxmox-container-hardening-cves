# AppArmor docviewd host demo

This demo builds a small C HTTP server and runs it directly on an Ubuntu host under a custom AppArmor profile. No Docker or other container runtime is required. The daemon is installed at `/usr/local/bin/docviewd`, runs as a dedicated non-root user, and listens only on `127.0.0.1:8080`.

## Requirements

Use a native Linux host or an Ubuntu VM with:

```bash
sudo apt update
sudo apt install -y gcc apparmor apparmor-utils auditd curl
sudo systemctl enable --now apparmor auditd
```

Check AppArmor support:

```bash
sudo aa-status
```

## Run

```bash
./run-demo.sh
```

The script compiles the program, installs the demo files under `/srv/docview`, loads the profile in complain mode, and starts `docviewd` as the `docview` user. This makes the first test run useful for observing the policy decisions before switching to enforcement.

## Test in complain mode

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/status
curl -i http://127.0.0.1:8080/forbidden-read
curl -i http://127.0.0.1:8080/forbidden-write
curl -i http://127.0.0.1:8080/forbidden-exec
```

In complain mode, the forbidden routes may succeed, but AppArmor should log the attempted violations.

View logs:

```bash
# Confirm that the running process is confined.
curl -s http://127.0.0.1:8080/status

# Kernel log view. In complain mode, look for ALLOWED rather than DENIED.
sudo journalctl -k --since '10 minutes ago' | grep -Ei 'apparmor=.*(ALLOWED|DENIED).*docviewd-demo|docviewd-demo.*apparmor='

# Audit log view. AVC/USER_AVC are SELinux filters, not AppArmor filters.
sudo ausearch -m APPARMOR_ALLOWED,APPARMOR_DENIED,APPARMOR_AUDIT -ts recent | grep docviewd-demo
```

If the curl response says that an action was blocked but no AppArmor record appears, verify that AppArmor is actually the layer making the decision:

```bash
# The process must show docviewd-demo, not unconfined.
curl -s http://127.0.0.1:8080/status
sudo aa-status | grep -A3 docviewd-demo

# DAC must allow the test action; otherwise AppArmor is not reached.
sudo -u docview test -r /srv/docview/secret.txt && echo "DAC allows secret read"
sudo rm -f /tmp/forbidden.txt
sudo -u docview sh -c 'echo dac-test >/tmp/docview-dac-test' && rm -f /tmp/docview-dac-test

# Search broadly; some systems log the executable path instead of only the profile name.
sudo journalctl -k --since '10 minutes ago' | grep -Ei 'apparmor|docview|secret|forbidden|dash'
sudo ausearch -m APPARMOR_ALLOWED,APPARMOR_DENIED,APPARMOR_AUDIT -ts today -i | grep -Ei 'apparmor|docview|secret|forbidden|dash'
sudo dmesg -T | grep -Ei 'apparmor|docview|secret|forbidden|dash'
```

## Switch to enforce mode

```bash
sudo aa-enforce /etc/apparmor.d/usr.local.bin.docviewd
sudo pkill -TERM -x docviewd
while pgrep -x docviewd >/dev/null; do sleep 0.2; done
sudo -u docview env DOCVIEW_BIND=127.0.0.1 /usr/local/bin/docviewd &
```

Run the same curl commands again. The forbidden routes should now fail with permission errors.

## Cleanup

```bash
sudo pkill -TERM -x docviewd
sudo apparmor_parser -R /etc/apparmor.d/usr.local.bin.docviewd
sudo rm -f /etc/apparmor.d/usr.local.bin.docviewd /usr/local/bin/docviewd
```
