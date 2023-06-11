# BLAKE3-AEAD

*an **experimental** authenticated cipher built entirely on top of the BLAKE3
hash function*

### Primary goals

- A drop-in replacement for AES-GCM in TLS-like use cases
- Maximum performance
- Defined in terms of the standard BLAKE3 API

### Nice-to-have features

- Nonces can be up to 64 bytes.
- Relatively large maximum message and AAD lengths: 2<sup>62</sup>-1 bytes
- The message and associated data can be processed in either order or in
  parallel, without knowing their lengths in advance, in one pass.
- Truncating the auth tag to N bits retains the expected O(2<sup>N</sup>) bits
  of security. (Correct?)
- A compact implementation can work directly with the BLAKE3 compression
  function and omit the tree hashing parts.

### Sharp edges

- Unique nonces are the caller's responsibility.
- Nonce reuse is catastrophic for security.
- Decryption has to either buffer the entire message or handle unauthenticated
  plaintext.
- No key commitment

Aside: All of these downsides are in common with AES-GCM and ChaCha20-Poly1305.
These TLS-oriented ciphers prioritize bytes on the wire and short-message
performance above all else, and in my opinion that makes them "hazmat" building
blocks, for experts only. BLAKE3-AEAD aims for the same use case and makes the
same tradeoffs. For a more general-purpose design with fewer sharp edges, see
[Bessie](https://github.com/oconnor663/bessie).

### Design

#### Some BLAKE3 background

This design relies on two features of BLAKE3 in particular. First, BLAKE3 has a
built-in keyed mode. This works by substituting the caller's key in place of
the standard IV, and it doesn't require any extra compressions.

Second, BLAKE3 supports extendable output. The blocks of the extended output
stream are produced by incrementing the compression function's internal `t`
parameter, which lets the caller compute blocks in parallel and seek to any
block in constant time. That parallelism makes the extended output useful as a
stream cipher, and it also benefits the "universal hash" construction below.
The range of the `t` parameter is large enough that we can use the high bits
for zero-overhead domain separation between the stream, the message
authenticator, and the associated data authenticator.

#### Universal hash

```python
def universal_hash(key, message, initial_seek):
    result = bytes(TAG_LEN)
    for i in range(0, len(message), BLOCK_LEN):
        block = message[i : i + BLOCK_LEN]
        seek = initial_seek + i
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        result = xor(result, block_output)
    return result
```

#### Encrypt

```python
def encrypt(key, nonce, aad, plaintext):
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN)
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash(key, ciphertext_msg, MSG_SEEK)
    aad_tag = universal_hash(key, aad, AAD_SEEK)
    tag = xor(stream[len(plaintext) :], xor(msg_tag, aad_tag))
    return ciphertext_msg + tag
```
