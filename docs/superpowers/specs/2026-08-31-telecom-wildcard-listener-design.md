# Telecom wildcard listener compatibility design

## Context

VM101 (`172.20.9.15`) runs the approved China Telecom client. Its
`plugin_monitor.exe` exposes an HTTP CONNECT proxy on TCP 8080 using the
wildcard IPv6 listener `[::]:8080`. From the client workstation, explicit
HTTP CONNECT through `172.20.9.15:8080` successfully reaches Google and
reports the telecom egress address. Plain HTTP forwarding and SOCKS5 are not
supported.

The existing server installer accepts only loopback listeners on TCP 8080.
That check prevents installation on the observed telecom client even though
the required CONNECT behavior works.

## Accepted PoC risk

For this PoC, remote reachability of VM101 TCP 8080 is accepted. The product
will neither create nor require an inbound firewall block for TCP 8080.
Consequently, another internal device may be able to use the telecom proxy
directly and bypass the product's TCP 18443 authorization boundary. This is a
documented PoC exception and must be reconsidered before production rollout.

## Server preflight behavior

The installer will accept exactly one TCP 8080 listener whose address is one
of `127.0.0.1`, `::1`, `0.0.0.0`, or `::`.

Before any product mutation, it must still prove all of the following:

1. TCP 8080 has exactly one listening socket and a valid owning PID.
2. The owning process is live and has a concrete executable path.
3. The executable has a valid Authenticode signature.
4. An HTTPS request to the approved Google probe succeeds through
   `http://127.0.0.1:8080` using HTTP CONNECT.

The evidence record will include the listener address/PID, executable path,
SHA-256, signature status and signer subject. Failure of any proof remains a
hard preflight failure.

## Firewall behavior

The installer will stop creating and owning
`RegenBioOverseasAccess-Block8080-Remote`. The product continues to create:

- an employee-CIDR-scoped inbound allow for TCP 18443; and
- the existing employee-scoped management-port protection.

Rollback and status logic will be updated so they expect only those two exact
product-owned firewall rules. Existing unrelated firewall policy is not
removed or modified.

## Data path

The Windows client captures traffic through its TUN interface and sends the
approved TCP flow to the VM101 Shadowsocks 2022 listener on TCP 18443. The
server sing-box instance uses an HTTP outbound pointed at
`127.0.0.1:8080`. The telecom client performs CONNECT and sends the request
over the approved overseas line.

The client must retain a direct host route to `172.20.9.15`, so the tunnel's
own TCP 18443 connection never recurses through the TUN or the workstation's
pre-existing local proxy.

## Tests and acceptance

Test-first coverage will prove:

- `[::]` and `0.0.0.0` listeners pass when identity, signature and CONNECT
  evidence are valid;
- multiple listeners, invalid PIDs, missing paths, invalid signatures and
  failed CONNECT probes fail before mutation;
- server installation creates exactly the TCP 18443 allow and management
  protection rules, with no product TCP 8080 rule;
- rollback and status remain exact and idempotent with the reduced rule set;
- all existing Go and dual-PowerShell suites remain green.

Live deployment proceeds only after a successful `-WhatIf` preflight. The
test does not change the workstation's existing proxy settings.
