# Windows Client Field Recovery Design

## Purpose

Make the Windows overseas-access client install the intended release, recover from its own stale Wintun device, connect quickly, load Google and YouTube with normal certificate validation, and remain connected beyond the five-minute runtime audit boundary.

This design is based on direct inspection of test endpoint `172.20.20.200`. It does not change the endpoint's configured physical-adapter DNS servers.

## Field Evidence

The endpoint reproduced four related field failures.

1. The installed artifact manifest reports product version `0.1.0` and source commit `5de032ad549a00d2b29bf9e99762365e6b694519`, although the intended test artifact was the signed `0.1.6` MSI. Seven same-name MSI registrations remain, all reporting version `0.1.0`.
2. While connected, Google and YouTube resolve to FakeIP addresses and route through the TUN, but Schannel returns `SEC_E_UNTRUSTED_ROOT`. The LocalMachine Root store contains the PoC code-signing certificate but no Go MITM root. Requests succeed with certificate verification disabled, proving that transport and the upstream HTTP proxy are reachable.
3. A failed or forced core termination can leave the product's Wintun device as `CM_PROB_PHANTOM`. Subsequent core starts hang while opening the same interface and exceed the ten-second readiness timeout. Removing that exact phantom instance with `pnputil` makes an otherwise identical SYSTEM launch create an Up adapter with `172.19.0.1` in less than one second.
4. A successful connection is deterministically terminated at five minutes. The runtime monitor audits the legacy prepared-firewall pool even though the minimal PoC state contains zero firewall rules. It reports `prepared_firewall: group membership drifted`, then the emergency path indexes the empty rule list and reports `NullArray`. Recovery restores ordinary networking.

## Chosen Approach

Use narrowly scoped recovery at each ownership boundary.

- The client may remove only a stale Wintun device whose interface name and description identify it as this product's TUN and only when no managed core process is running. It must not enumerate and remove arbitrary Wintun, TAP, VPN, or third-party adapters.
- Runtime firewall auditing and emergency protection remain enabled when the captured prepared state actually owns firewall definitions. The minimal PoC path, whose current state has no prepared firewall rules, does not run legacy pool membership checks and does not index nonexistent emergency rules.
- The MSI performs a real upgrade to the intended product version, removes superseded registrations through Windows Installer upgrade semantics, installs the Go MITM root transactionally, and leaves one authoritative product registration.
- Diagnostics expose enough core output and cleanup detail to distinguish interface initialization, certificate trust, and runtime audit failures without weakening secret redaction.

Broad Wintun deletion and globally disabling firewall monitoring are explicitly rejected because they can disrupt other VPN software and weaken the fail-closed boundary.

## Components

### Product-Owned Wintun Recovery

Before starting sing-box, the Windows core-launch path checks for a stale device matching the configured product interface name. Recovery is allowed only when:

- no managed sing-box process from the product installation directory is alive;
- the device is not operational;
- the PnP instance belongs to Wintun; and
- its interface name or description matches the product-configured TUN.

The recovery operation removes the exact PnP instance ID and then verifies that the instance is absent before launch. An active or ambiguous adapter causes a fail-closed error rather than deletion. Cleanup is idempotent when no stale device exists.

### Runtime Monitor Applicability

The monitor derives whether prepared-firewall protection applies from the current captured state, not from legacy firewall groups that happen to remain on the machine.

- A state with owned prepared firewall rules continues to receive periodic membership audits and emergency protection.
- A state with zero prepared firewall rules skips those two operations while continuing core-process, TUN, route, and other applicable runtime checks.
- Emergency protection validates rule indices before use and returns a typed diagnostic instead of a PowerShell `NullArray` failure if inconsistent state reaches it.

This preserves strict behavior for modes that own a kill-switch while preventing the minimal PoC from auditing state it never created.

### Installer Upgrade and Trust

The release MSI must:

- report the intended semantic product version in both Windows Installer metadata and `artifact-manifest.json`;
- use stable UpgradeCode and versioned ProductCode behavior so installing a newer MSI upgrades older registrations;
- remove superseded product registrations and payload before committing the new registration;
- install the bundled Go MITM root into `Cert:\LocalMachine\Root` using the existing transactional custom-action design;
- roll back files, registration, and certificate state together on failure; and
- provide post-install verification for version, source commit, signature, service binary paths, and certificate thumbprint.

The test deployment must use the artifact's SHA-256 digest rather than relying on a filename that may identify an older build.

### Diagnostics

The supervisor retains a bounded, redacted tail of core stderr for readiness failures instead of discarding all output. User-visible diagnostics remain sanitized and must not include credentials or private material. Trace records identify whether a failed start was caused by stale-device recovery, process launch, TUN readiness, or certificate validation.

## Error Handling and Recovery

- If the exact stale product device cannot be safely proven, connection fails without deleting it and reports the instance identity needed for diagnosis.
- If removal fails, the client does not launch another core on top of uncertain device state.
- If core readiness times out, termination remains proven before recovery continues; the trace includes the bounded redacted core log tail.
- If a firewall-backed mode detects genuine drift, it retains the existing fail-closed disconnect and recovery behavior.
- If MSI certificate installation or upgrade verification fails, Windows Installer rolls the transaction back.
- Ordinary physical-adapter DNS configuration is not modified by this work.

## Test Strategy

Implementation follows test-driven development.

1. Unit tests model absent, active, ambiguous, and product-owned phantom Wintun instances. The regression test must fail before stale-device recovery exists.
2. Controller and monitor tests prove that zero-rule PoC state skips legacy firewall audit/emergency calls while a rule-owning state still invokes them and disconnects on real drift.
3. PowerShell and MSI inspection tests prove stable upgrade metadata, one authoritative registration after upgrade, correct manifest version, and transactional Go MITM root installation.
4. Supervisor tests prove readiness failures retain only bounded, redacted core diagnostics.
5. Existing Go, integration, and Pester suites remain green.
6. On `172.20.20.200`, install the newly hashed signed MSI and verify:
   - one installed product registration with the expected version and source commit;
   - the expected Go MITM root thumbprint in LocalMachine Root;
   - first connect and reconnect complete quickly;
   - Google and YouTube return successful HTTPS responses without insecure flags;
   - the connection stays healthy beyond two runtime audit intervals; and
   - disconnect leaves zero product TUNs, routes, core processes, and active firewall residue.

## Acceptance Criteria

- A clean or previously failed Windows 10 endpoint connects without requiring a reboot or manual PnP cleanup.
- Google and YouTube pass normal Schannel certificate validation while connected.
- The minimal PoC remains connected for at least ten minutes under active traffic.
- Firewall-owning modes retain periodic drift detection and fail-closed recovery.
- Unrelated VPN/TUN/TAP devices are never removed or changed.
- Upgrade leaves one authoritative installation and the intended release identity.
- All automated tests pass, the release MSI is signed and hashed, the field PoC passes, and all project changes are committed to Git.

## Deferred Work

UI redesign, broader security hardening, and performance tuning beyond the fixes required for this field PoC remain out of scope until the acceptance criteria above pass.
