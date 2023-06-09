BLAKE3-AEAD, an **experimental, unreviewed** cipher built entirely on the
BLAKE3 hash.

Primary goals:
- a drop-in replacement for AES-GCM in TLS-like use cases
- maximum performance
- defined in terms of the standard BLAKE3 API

Nice-to-have features:
- support for nonces up to 64 bytes
- relatively large maximum message and AAD lengths: 2<sup>62</sup> bytes
- truncated n-bit auth tags provide 2<sup>n</sup> bits of security

Personal soapbox: Modern AEAD ciphers like AES-GCM and ChaCha20-Poly1305, which
BLAKE3-AEAD aims to imitate, are not user-friendly tools. They're purpose-built
for protocols like TLS, and what TLS needs is very different from what
higher-level security applications need. Applications often have long-lived
symmetric keys, which require large random nonces, ideally generated below the
API instead of leaving randomness to the user. Applications often encrypt large
files, and they need an efficient way to decrypt those files without handling
unauthenticated plaintext. Lots of communication applications need key
commitment, often without realizing it. Standard AEAD ciphers provide none of
these things. BLAKE3-AEAD makes only a small improvement here: large nonces are
supported, but it's still up to the user to generate them correctly. So like
AES-GCM and ChaCha20-Poly1305, BLAKE3-AEAD is an *experts-only* tool. For a
design that aims to serve application programmers better, see
[Bessie](https://github.com/oconnor663/bessie).
