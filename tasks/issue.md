### Summary

Control UI WebSocket connections bypass the configured gateway.auth.mode and always use device pairing auth, even when trusted-proxy mode is configured with a valid user header and trusted proxy CIDR.

### Steps to reproduce

1. Configure gateway with trusted-proxy auth behind a reverse proxy that injects a user header:
   ```json
   {
     "gateway": {
       "auth": {
         "mode": "trusted-proxy",
         "trustedProxy": { "userHeader": "x-authentik-username" }
       },
       "trustedProxies": ["10.19.0.0/16"],
       "controlUi": {
         "allowedOrigins": ["https://openclaw.example.com"]
       }
     }
   }
   ```
2. Access the Control UI through the reverse proxy (Traefik forwardAuth injecting the user header)
3. Observe "pairing required" error instead of automatic authentication

### Expected behavior

When gateway.auth.mode is "trusted-proxy", Control UI should identify the user via the configured trustedProxy.userHeader and skip device pairing entirely.

### Actual behavior

Control UI always initiates device pairing. Logs show deviceId/requestId/reason:"not-paired" with NO authMode or authProvided fields — the trusted-proxy code path is never entered for Control UI connections.

Compare CLI (correctly enters trusted-proxy path):
{ "authMode": "trusted-proxy", "authProvided": "token", "authReason": "trusted_proxy_untrusted_source" }

Control UI (skips trusted-proxy entirely):
{ "cause": "pairing-required", "deviceId": "2e2963b0...", "requestId": "5addf508-...", "reason": "not-paired" }

### OpenClaw version

2026.2.23

### Operating system

Kubernetes (Talos Linux) / accessed from Windows 11 + Edge 145

### Install method

docker (Helm chart, single replica)

### Logs, screenshots, and evidence

```shell
Full pairing-required log entry (Control UI connection):
  {
    "cause": "pairing-required",
    "handshake": "failed",
    "durationMs": 42,
    "host": "openclaw.example.com",
    "origin": "https://openclaw.example.com",
    "forwardedFor": "192.168.1.98",
    "deviceId": "2e2963b072fe1cfa5bbc3e5bb35145313fe5df1ae14224d12d054bd81fea71f4",
    "requestId": "5addf508-a579-4334-9ee2-7aaa38d918c1",
    "reason": "not-paired"
  }

  CLI connection (same gateway, correctly enters trusted-proxy auth):
  {
    "cause": "unauthorized",
    "authMode": "trusted-proxy",
    "authProvided": "token",
    "authReason": "trusted_proxy_untrusted_source"
  }
```

### Impact and severity

Affected: All Control UI users behind a reverse proxy using trusted-proxy auth mode
Severity: High (blocks web UI access entirely)
Frequency: 100% repro
Consequence: Must set dangerouslyDisableDeviceAuth: true and rely solely on external auth layer (e.g. Authentik + network policies), defeating the purpose of trusted-proxy auth mode

### Additional information

Workaround: controlUi.dangerouslyDisableDeviceAuth: true

Related issues:

- #23585 — trusted-proxy header absent on WS upgrades via Cloudflare
- #22299 — loopback mode rejects internal connections with pairing required
