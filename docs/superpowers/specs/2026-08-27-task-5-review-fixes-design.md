# Task 5 Review Fixes Design

## Scope

Harden the Windows forwarding PoC evidence chain so a `PASS` can only be produced from one fresh, chronological run of a validated configuration, while preserving create-new artifact writes and never handling the telecom PIN.

## Evidence contract

Every inventory, probe, and monitor artifact carries schema version 1, a caller-selected run ID, the SHA-256 digest of the validated normalized configuration, and UTC capture timestamps. Inventory evidence contains interfaces, routes, WinNAT records, and normalized firewall records. Probe evidence contains the exact configured target name and URL plus the transport observations for that target. The down-state monitor is a fifth required artifact and records the interval in which the native probe ran and whether the telecom path reappeared.

JSON decoding rejects unknown fields and trailing values. The verdict command requires `--config` and `--run-id`; it recalculates the configuration digest and checks all artifacts against both inputs. Empty synthetic inventories/probes, stale or future evidence, mixed identities, and invalid chronology are inconclusive.

## Verdict semantics

Probe normalization produces two independent facts: healthy HTTPS (complete 2xx response) and path reachability. A completed TCP connection, TLS outcome, any HTTP response, or a body-read failure after an HTTP response proves reachability. Field/error-code combinations are validated as a state machine so contradictory records are inconclusive.

Metadata validity for the down artifact is checked before consuming its reachability records. A valid reachable down-state target has safety precedence over missing sibling artifacts and malformed sibling records. Otherwise, malformed evidence is inconclusive. Exact drift in interfaces (including forwarding), routes, NAT, or firewall state fails the gate. A recorded automatic telecom reconnect fails the gate.

## No-leak orchestration

The script accepts only a file named `poc-probe.exe` and a caller-supplied SHA-256, validates both before disconnect, and rejects script wrappers. It obtains the strict configuration metadata from the trusted native binary, then prompts for manual disconnect. From that point onward a `finally` always gives the manual reconnect reminder and verifies restoration.

The script confirms absence of only the configured telecom default/external prefixes, starts the native probe as a process, and polls the telecom adapter and configured route set throughout the process lifetime, including a final race-closing sample. Any automatic reconnect is recorded in create-new monitor evidence, the probe is stopped, and the script fails. Native non-zero exit and missing output also fail.

## Tests

Go tests cover strict configuration, digest/identity binding, unknown JSON fields, structural/freshness/chronology rejection, exact state drift, target URL binding, transport reachability, contradictory records, and leak precedence. Pester 3.4 behavior tests cover native identity/hash rejection, real telecom-route shapes, native probe exit failure, reconnect reminder/failure, and automatic-reconnect races without touching real networking.
