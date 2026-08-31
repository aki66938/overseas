# Task 10 Final Trust-Boundary Design

## Scope

Close three remaining non-live false-pass paths without running the integration
environment or touching VM/physical-host state: direct credential provisioning,
SSH known-host pinning, and server WhatIf firewall comparison.

## Direct provisioning trust

Keep the runbook's direct `fixture-action provision-credential` entry point, but
require one fixed CLI contract containing externally supplied lowercase SHA256
digests for the action config, generated credentialless client config, credential
source executable, and remote server attestation. These values must come from the
already verified signed fixture/release contract or an independently approved
operator ledger; deriving them from the files being checked is forbidden.

The helper hashes the action-config bytes before parsing them. After strict
parsing, it requires the internal credential-source and attestation hashes to
equal their external values, hashes the generated client and attestation bytes
before parsing either, validates the strict remote attestation, and hashes the
source executable against the external value immediately before execution. Any
missing, reordered, placeholder, uppercase, or mismatched value fails closed.

## SSH trust

Do not construct trust from `ssh-keyscan`. Accept exactly one independently
approved known-host public-key line with the exact host token
`DESKTOP-1BVR2H6`, key type `ssh-ed25519`, and one base64 key token. Create the
run-owned known_hosts file exclusively, reject reparse points, re-read exactly
one identical line, and require `ssh-keygen -lf -E sha256` to emit exactly one
fingerprint equal to the separately approved SHA256 fingerprint. Every SSH
invocation pins `HostKeyAlgorithms=ssh-ed25519`, strict checking, and that file;
the same fingerprint is embedded in the attestation contract.

## WhatIf firewall surface

Capture only the three server-owned rule names:

- `RegenBioOverseasAccess-AllowEmployee-In`
- `RegenBioOverseasAccess-Block8080-Remote`
- `RegenBioOverseasAccess-BlockManagement-Employee`

For each name, reject duplicates and emit a deterministic ordered record for
absence or for the complete stable rule definition: ownership `Description`,
rule fields, and application, port, address, service, interface alias/type, and
security filters. Sort multi-valued fields before JSON serialization. Do not use
the mutable firewall Group as the ownership selector. The existing canonical
before/after JSON comparison remains the executable zero-drift gate.

## Verification

Each boundary gets a witnessed focused RED then GREEN test. Final evidence is the
locked full Go test/vet gate, locked 20x repetition set, PowerShell 5.1 and 7 full
Pester suites, eight locked Windows builds, repository PowerShell AST parse,
diff check, secret scans, report update, clean commit, and an empty worktree.
