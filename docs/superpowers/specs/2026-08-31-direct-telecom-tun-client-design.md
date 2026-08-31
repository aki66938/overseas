# Direct telecom TUN client design

## Context and decision

VM101 (`172.20.9.15`) exposes the approved China Telecom HTTP CONNECT
service on TCP 8080. A workstation can reach Google through
`http://172.20.9.15:8080`, but VM101 cannot use either its loopback or its own
LAN address to connect back to that listener. When the VM bypasses its system
proxy, direct Google access times out. Therefore a sing-box server on VM101
cannot use the telecom listener as its upstream.

The PoC will remove that unnecessary server hop. The Windows workstation's
sing-box instance will capture traffic with its TUN interface and use an HTTP
CONNECT outbound pointed directly at `172.20.9.15:8080`.

## Data path

The complete path is:

`Windows application -> local sing-box TUN -> HTTP CONNECT 172.20.9.15:8080 -> telecom overseas line`

Applications do not need proxy support or proxy settings. The client retains
an explicit direct host route for `172.20.9.15`, so its upstream connection
cannot recurse into the TUN. Corporate CIDRs and approved corporate DNS
remain outside the overseas path. The existing fail-closed route, DNS and
firewall behavior remains in force while the client is connected.

VM101 keeps the telecom software and its existing TCP 8080 listener. This PoC
does not install the RegenBio server service, open TCP 18443, or modify VM101
firewall policy.

## Client configuration and installer

The signed Windows package will install the existing client agent, UI,
sing-box and Wintun payloads. Its generated sing-box configuration will use a
single HTTP outbound with server `172.20.9.15` and port `8080`; it will not
contain a Shadowsocks credential or a server-service dependency.

The upstream address and port are non-secret, release-bound configuration.
Installation must finish with the service stopped and the UI disconnected.
The installer must not alter the workstation's current FlClash/system proxy
or start the TUN automatically.

## Operational ownership

Codex is responsible for source changes, automated tests, compilation,
signature verification and local installation. The user owns the live
acceptance test:

1. confirm the new client is initially disconnected;
2. close FlClash and confirm its system/TUN proxy is no longer active;
3. start the RegenBio client once;
4. verify ordinary applications can reach approved overseas sites without
   application proxy settings;
5. disconnect the RegenBio client before restarting FlClash.

The live test is not claimed successful until the user reports its result.

## Safety and recovery

Before installation, record the local route, DNS, firewall and service
baseline. Installation is allowed while FlClash remains active because the
new service stays stopped. Before the user's live test, stage a time-bounded
recovery command that stops the new service and invokes its restore path if
the user loses connectivity. No command in this work may close or reconfigure
FlClash.

If connection startup, readiness or network activation fails, the client must
restore its captured baseline and remain disconnected. Uninstall and repair
retain the existing exact-ownership and resumable cleanup guarantees.

## Tests and acceptance

Test-first coverage must prove:

- client rendering produces exactly one HTTP outbound to
  `172.20.9.15:8080` and no Shadowsocks outbound;
- the upstream host route bypasses the TUN;
- malformed, loopback, wildcard or unapproved upstream endpoints fail before
  any network mutation;
- client installation completes with the service stopped and does not touch
  system proxy or FlClash state;
- disconnect and startup failure restore the exact captured network state;
- all Go and dual-PowerShell regression suites remain green;
- the rebuilt MSI has a valid signature from the approved PoC signer and its
  extracted payload hashes match the signed release manifest.

Automated verification and installation are separate from live acceptance.
The final user-run test must be performed only after FlClash is closed.
