### Task 10: Complete and Execute the Windows Physical-Host Acceptance Gate

**Status:** blocked from live execution until the code prerequisites below are implemented and reviewed. A non-live Task 9 PASS is not authorization to set `OVERSEAS_ACCESS_INTEGRATION=1`.

**Code prerequisites carried from Task 9 review:**

- [ ] Bind the exact corporate CIDR list, corporate DNS addresses, and internal suffixes in the signed action/config contract. Validate every client direct route and direct DNS server against that allowlist; require suffix label boundaries.
- [ ] Parse and lock the complete signed client payload manifest. During `case-setup`, invoke the installed manifest-pinned credential provisioner using pipe-only input derived from the locked fixture client config, then start the agent. Do not place credential plaintext in argv, evidence, logs, or temporary files.
- [ ] Capture every payload-manifest installed file and its expected hash, plus unexpected files in both owned roots. Require exact setup hashes and complete uninstall absence before cleanup.
- [ ] Bind the production `overseas-server-service.exe`, its locked server config, service identity, client-facing listener PID/image hash, and underlying core identity. Either run it locally under reviewed ownership or add a cryptographically bound remote attestation; a compatible unowned listener is insufficient.
- [ ] Add integrated non-live backend tests proving the clean-baseline setup/credential/runtime-config sequence and server/payload false-pass refusals.

**Authorized-host acceptance after prerequisites:**

- [ ] Stage corporate-signed, ACL-protected artifacts and detached manifests on the designated disposable physical Windows host.
- [ ] Run elevated dry-run/preflight and preserve its evidence.
- [ ] Obtain explicit stop/go approval, use a new empty baseline directory, and run all nine live scenarios plus 20 lifecycle repetitions.
- [ ] Preserve nonce/leak receipts, action-local snapshots, process-tree timeout evidence, and exact zero-drift final state.

The developer workstation is not the designated host. Do not mutate its routes, DNS, firewall, services, adapters, installer state, or runtime configuration.
