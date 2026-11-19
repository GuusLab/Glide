# Security

Glide is v0.4 and has **not been audited**. The cryptography is built from well known parts (SPAKE2, Noise NNpsk0, AES-256-GCM, ChaCha20-Poly1305, BLAKE3), but the way they are put together has not been reviewed by a third party, and neither has the SPAKE2 implementation it depends on. Do not rely on Glide to protect sensitive data until it has been.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through [GitHub's private vulnerability reporting](https://github.com/GuusLab/Glide/security/advisories/new), or email **guus@guuslab.com** with "Glide security" in the subject.

Include what you found, how to reproduce it, and which version or commit you tested. You will get a reply within a few days. Once a fix is ready, the issue will be disclosed together with it, and you will be credited unless you prefer not to be.

## What Glide is meant to withstand

**Somebody on the network who does not know the secret.** They can read, drop, replay and change bytes on any stream. They should learn nothing about the files beyond their approximate total size and timing, and should not be able to make the receiver accept a byte the sender did not send. A recorded handshake gives them nothing to test guesses at the secret against; guessing takes one live connection per guess, and the sender stops after a small number of failures.

**A sender who knows the secret and is hostile.** Knowing the secret lets a sender offer files, and nothing more. The receiver checks the whole manifest before it creates anything, writes only inside the output folder, follows no symbolic link on the way there, and bounds every allocation by what has already been authenticated.

**A receiver who knows the secret and is hostile.** They can read the files, which is what the secret is for. They cannot read anything outside the folder being sent (symbolic links are not followed) and cannot make the sender queue an unbounded amount of work.

## What it does not protect against

- A secret that is too easy. Six digits and a limit of 20 failed handshakes is a one in fifty thousand chance per attempt; use a longer secret for anything that matters or that stays open for long.
- Somebody else on the same machine: the secret on a command line is visible in the process list (use the `GLIDE_KEY` environment variable), and the output folder is assumed not to be changed by another process during a transfer.
- Traffic analysis. Block sizes and counts are visible, and compression means the size on the wire depends on the content.
- Denial of service. Anybody who can reach a listener can use up its failed handshake allowance, and anybody on the path can stop a transfer.

## Scope

In scope: the wire protocol in [docs/PROTOCOL.md](docs/PROTOCOL.md), the handshake, key derivation, block encryption and verification, the checks on the manifest and on output paths, and anything that lets a peer without the secret read, change or inject data, lets a peer with the secret read or write outside the folders involved, or crashes the other side.

Out of scope: weak secrets chosen by the user, and the denial of service described above.
