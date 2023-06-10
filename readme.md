# BLAKE3-AEAD

*an **experimental** authenticated cipher built entirely on top of the BLAKE3
hash function*

### Primary goals

- A drop-in replacement for AES-GCM in TLS-like use cases
- Maximum performance
- Defined in terms of the standard BLAKE3 API

### Nice-to-have features

- Nonces can be up to 64 bytes.
- Relatively large maximum message and AAD lengths: 2<sup>62</sup> bytes
- The plaintext and the associated data can both be processed incrementally,
  without knowing their lengths in advance, in either order or in parallel.
- Truncating the auth tag to n bits retains the expected O(2<sup>n</sup>) bits
  of security.
- A compact implementation could work directly with the BLAKE3 compression
  function and omit the tree hashing parts.

### Sharp edges

- Unique nonces are the caller's responsibility.
- Nonce reuse is catastrophic for security.
- Decryption needs to buffer the entire message.
- No key commitment

Aside: All of these downsides are in common with AES-GCM and ChaCha20-Poly1305.
These ciphers prioritize bytes on the wire and short-message performance above
all else, and in my opinion that makes them "hazmat" building blocks for
experts only. BLAKE3-AEAD isn't about changing that. For a different design
that _is_ about changing that, see
[Bessie](https://github.com/oconnor663/bessie).

### Design

#### Some BLAKE3 background

There are two important features of BLAKE3 that get used heavily in this
design. First, BLAKE3 has a built-in keyed mode. It works by substituting the
caller's key in place of the standard IV, and crucially that means it doesn't
require any extra compressions.

Second, BLAKE3 supports extendable output. The blocks of the extended output
stream are produced by incrementing the internal `t` parameter to the
compression function, which lets the caller compute blocks in parallel or
"seek" to any block in constant time. This parallelism makes the extended
output suitable as a stream cipher, and the range of the `t` parameter is large
enough that we can use the high bits for zero-overhead domain separation.

#### Universal hash

```python
def universal_hash(key, message, initial_block_counter):
    result = bytes(TAG_LEN)
    for i in range(0, len(message), BLOCK_LEN):
        block = message[i : i + BLOCK_LEN]
        seek = BLOCK_LEN * initial_block_counter + i
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        result = xor(result, block_output)
    return result
```

#### Encrypt

```python
def encrypt(key, nonce, aad, plaintext):
    assert len(nonce) <= MAX_NONCE_LEN
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN)
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash(key, ciphertext_msg, MSG_HASH_COUNTER)
    aad_tag = universal_hash(key, aad, AAD_HASH_COUNTER)
    tag = xor(stream[len(plaintext) :], xor(msg_tag, aad_tag))
    return ciphertext_msg + tag
```
