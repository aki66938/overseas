# Controlled credential provisioning

The MSI intentionally installs `RegenBioOverseasAccessAgent` stopped. A release operator must provision the machine-scoped DPAPI credential before starting it.

Run from an elevated deployment process whose standard output is an approved in-memory secret stream. The producer must emit exactly one UTF-8 JSON document and must not log its output:

```powershell
& 'C:\Program Files\ApprovedSecretBroker\secret-broker.exe' emit-regenbio-overseas-json --secure-inherited-handle |
    & 'C:\Program Files\RegenBio\OverseasAccess\credential-provisioner.exe'
if ($LASTEXITCODE -ne 0) { throw 'Credential provisioning failed.' }
```

Required JSON schema:

```json
{"method":"2022-blake3-aes-128-gcm","password":"REDACTED","expires_at":"2026-08-30T00:00:00Z"}
```

Do not put the JSON in a file, environment variable, command argument, transcript, or deployment log. The provisioner rejects interactive terminal input, unknown fields, expired data, and input over 64 KiB. It writes only `C:\ProgramData\RegenBio\OverseasAccess\credential.bin` through machine-scope DPAPI with SYSTEM/Administrators-only ACLs and clears its input buffers.

After generic success, verify the encrypted blob ACL without reading it, start the service, and require the initial controller state to remain disconnected:

```powershell
$path = 'C:\ProgramData\RegenBio\OverseasAccess\credential.bin'
& "$env:WINDIR\System32\icacls.exe" $path
if ($LASTEXITCODE -ne 0) { throw 'Credential ACL inspection failed.' }
Start-Service -Name RegenBioOverseasAccessAgent
$response = '{"id":"deployment-proof","action":"status"}'
# Send through the locked RegenBioOverseasAccess named pipe and require state=disconnected.
```

The example broker name documents the required interface; deployment must substitute the organization's approved broker that can write the JSON directly to the inherited pipe.

