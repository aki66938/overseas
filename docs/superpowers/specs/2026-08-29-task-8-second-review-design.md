# Task 8 Second Review Design

The signed artifact manifest and detached CMS signature are the two trust-root objects. The manifest hashes every other MSI payload exactly once. Deferred MSI actions receive only validated CustomActionData: payload verification runs after files, firewall installation/rollback runs after verification and before service installation, and sensitive runtime cleanup runs after process termination with an ownership ledger and residue proof.

`credential.bin` and `sing-box.json` are runtime-owned sensitive files recorded in a fixed protected ledger. Cleanup is idempotent, exact-path-only, post-stop, and leaves the ledger/journal until deletion and root residue are proven. Release production occurs in a unique temporary tree and publishes by atomic rename only after signing and inspection. The build actively verifies Go/WiX versions and locked package hashes. Wintun uses the official Prebuilt Binaries License label and exact distributed license text.

Tests never mutate live installer state. Pester inspects source and raw MSI tables; Go tests exercise argument/ownership contracts; final verification builds, extracts, and inspects only an inspect-only MSI.
