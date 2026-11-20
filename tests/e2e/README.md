# End-to-end tests

Each script installs the real release package with `install.sh` in a Debian 13 container that boots systemd. It then drives the real agent over its socket, and uses real DHCP clients in network namespaces as the devices.

| Script | What it proves |
|---|---|
| `zero-trust.sh` | Holding zone, approve, remove, block, capture, an automatic undo, a boot without the agent, and the README's emergency commands |
| `fixed-address.sh` | Fixed addresses with Zero Trust off and on, moving one, and approving a device that has one |
| `system.sh` | System page readings against `free`, `df` and `nproc`, and history across a restart |
| `names.sh` | Device names: duplicates, reserved names, makers, a rename, a per-device filter level, Zero Trust, and a restart |
| `upgrade-names.sh` | Upgrading a running v1.5.1 firewall keeps the names devices already gave |
| `speed.sh` | Speed tests with Ookla's real program: terms first, a test by hand, a scheduled one, a tampered program re-fetched, a restart. **Runs two real tests, about 200 MB of data.** |

Run one:

```powershell
pwsh deploy/publish.ps1
pwsh tests/e2e/run.ps1 names
```

Each test needs Docker with privileged containers. Each ends with a line `RESULT: n passed, m failed`.
