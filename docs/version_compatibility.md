# Version Compatibility

[中文文档](version_compatibility_zh.md)

Both ends of every `rats_tls` link must run a build that includes post-handshake attestation. There is no transitional mode.

| Compatible Version Range | Description |
| --- | --- |
| Post-handshake attestation cutover | Evidence is no longer carried in the X.509 certificate. Peers that still embed DICE tagged evidence in the certificate cannot complete a `rats_tls` connection with an upgraded peer. TLS session resumption and 0-RTT are disabled. Upgrade ingress and egress together. |
