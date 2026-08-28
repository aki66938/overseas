# Task 8 Installer Remediation Design

## Scope and trust boundary

Task 8 remains a Windows-only, per-machine WiX v4 package plus a development lifecycle harness. The checked-in default build is explicitly `inspect-only`: it embeds an impossible corporate signer thumbprint and must abort before `InstallInitialize`. A distributable release exists only after an out-of-repo signing input produces signed payload metadata and an Authenticode-signed MSI whose signer matches the compile-time corporate thumbprint. No private key, password, credential, or development key enters Git, MSI properties, process arguments, logs, or registry.

## MSI gates and upgrade behavior

The MSI has two checked gates:

1. An immediate, pre-`InstallInitialize` action reads `OriginalDatabase`, requires a valid Authenticode signature, and compares its leaf certificate thumbprint with the compile-time corporate trust anchor. It runs for install, repair, and upgrade. The default inspect-only thumbprint cannot match a real certificate.
2. A deferred, no-impersonate action after `InstallFiles` and before `InstallServices` validates the installed signed payload manifest, its detached CMS signer, every installed file hash, and required Authenticode signatures. Service, firewall, shortcut, and service start follow only after this proof.

The controlled-disconnect action runs during ordinary uninstall and during major-upgrade removal. It has no `UPGRADINGPRODUCTCODE` exclusion and must complete before the old service or files are removed. Any response other than exact `StateDisconnected` aborts the transaction.

## Exact ownership and durable lifecycle transactions

The harness treats Program Files and ProgramData parent directories as containers, never as wholly owned foreign trees. Before mutation it refuses pre-existing unowned roots, the shortcut, service name, and exact firewall rule names. It writes a durable transaction record before each resource creation and publishes a per-root ownership marker as soon as a root is created. Journal phases are monotonic and include exact created resources.

Install compensation runs in reverse dependency order and removes only resources recorded in the journal with matching markers. Repair and uninstall resume from durable phases after interruption. On failure they either compensate safely or retain journal/ownership proof for the next invocation. Ownership markers and the transaction journal are deleted last, only after exact service, TUN, route, DNS, firewall, shortcut, file, and directory residue checks pass.

## Credential provisioning

A dedicated Windows console executable reads one JSON credential document only from standard input, rejects interactive-console stdin, applies strict size and schema limits, and calls `secret.StoreMachine` at the fixed `C:\ProgramData\RegenBio\OverseasAccess\credential.bin` path. The caller buffer and parsed password bytes are zeroed. It emits only generic success/failure text, accepts no credential-bearing command-line flag, and relies on StoreMachine's service/admin-only ACL. The installer leaves the agent service stopped until this file exists; controlled deployment provisions the credential first and then starts the service.

## Artifact provenance and inspection

A tracked build lock records WiX/extensions, Go, sing-box, Wintun, trust-anchor mode, and source URLs/hashes. A tracked PowerShell recipe stages the exact payload allowlist, gives official Wintun `LICENSE.txt` its own filename and attribution, emits a canonical artifact manifest, SBOM, and SHA-256 checksum file, and signs the artifact manifest only with an explicitly supplied out-of-repo certificate. The MSI packages both manifest and detached CMS signature.

Inspection decompiles and extracts the MSI, compares every extracted payload byte/hash to the signed source manifest, verifies required Authenticode/CMS signatures, reads raw MSI tables for gate ordering and security metadata, and recursively scans extracted content for secret/private-key material. Generated artifacts remain ignored; the lock, recipe, tests, and evidence format remain tracked and tied to the source commit.

## Testing

TDD slices cover: unsigned/wrong-signer MSI refusal before mutation, install/repair gate sequencing, upgrade disconnect ordering and exact disconnected-state refusal, collisions with unowned roots/shortcut/service/firewall, partial repair/uninstall resume, deletion of proof last, stdin-only credential provisioning and buffer clearing, disconnected-until-provisioned behavior, distinct Wintun attribution, exact artifact manifest/SBOM/checksums, recursive secret scanning, and extracted-byte/signature comparisons. Final verification runs focused Pester under Windows PowerShell 5.1 and PowerShell 7, the full Pester suite, all Go tests and vet, Windows builds, WiX build, raw table inspection, extraction, and source-to-package comparison without live installer mutation.
