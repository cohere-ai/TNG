# Version Compatibility

[中文文档](version_compatibility_zh.md)

1.0.0 cannot complete a `rats_tls` connection with 0.7.0 or earlier. There is no transitional mode. Upgrade ingress and egress together.

| Compatible Version Range | Description |
| --- | --- |
| >= 1.0.0 | RATS-TLS no longer carries evidence in the X.509 certificate. Attestation is a post-handshake JSON exchange, and TLS session resumption and 0-RTT are disabled. `verify` accepts a list of verifiers. A peer that still embeds DICE tagged evidence in the certificate, or that speaks the previous exchange, cannot connect. |
