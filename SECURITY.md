# Security

Glide is v0.3 and has **not been audited**. The cryptography is built from well known parts (Noise NNpsk0, AES-256-GCM, ChaCha20-Poly1305, BLAKE3), but the way they are put together has not been reviewed by a third party. Do not rely on Glide to protect sensitive data until it has been.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through [GitHub's private vulnerability reporting](https://github.com/GuusLab/Glide/security/advisories/new), or email **guus@guuslab.com** with "Glide security" in the subject.

Include what you found, how to reproduce it, and which version or commit you tested. You will get a reply within a few days. Once a fix is ready, the issue will be disclosed together with it, and you will be credited unless you prefer not to be.

## Scope

In scope: the wire protocol in [docs/PROTOCOL.md](docs/PROTOCOL.md), the handshake, key derivation, block encryption and verification, and anything that lets a peer without the key read, change or inject data, or crash the other side.

Out of scope: weak secrets chosen by the user, and denial of service by someone who already has the key.
