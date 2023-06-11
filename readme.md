# BLAKE3-AEAD

*an **experimental** authenticated cipher built entirely on top of the BLAKE3
hash function*

## Primary goals

- A drop-in replacement for AES-GCM in TLS-like use cases
- Maximum performance
- Defined in terms of the standard BLAKE3 API

## Nice-to-have features

- Nonces can be up to 64 bytes.
- Relatively large maximum message and AAD lengths, 2<sup>62</sup> and
  2<sup>62</sup>-1 bytes respectively.
- The message and associated data can be processed in in parallel, without
  knowing their lengths in advance, in one pass.
- Truncating the auth tag to N bits retains the expected O(2<sup>N</sup>) bits
  of security. (Correct?)
- A compact implementation can work directly with the BLAKE3 compression
  function and omit the tree hashing parts.

## Sharp edges

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

## Design

### Some BLAKE3 background

This design relies on two features of BLAKE3 in particular. First, BLAKE3 has a
built-in keyed mode. This works by substituting the caller's key in place of
the standard IV, and it doesn't require any extra compressions.

Second, BLAKE3 supports extendable output. Extended output blocks are produced
by incrementing the compression function's internal `t` parameter, which allows
for computing blocks in parallel or seeking to any point in the output stream.
This makes the extended output a natural stream cipher, and it also lets us use
seeking for domain separation, similar to the tweak in a tweakable block
cipher.

### Universal hash

This Python example and the others below are excerpted from
[`blake3_aead.py`](python/blake3_aead.py).

```python
TAG_LEN = 16
BLOCK_LEN = 64

def universal_hash(key, message, initial_seek):
    output = bytes(TAG_LEN)
    for i in range(0, len(message), BLOCK_LEN):
        block = message[i : i + BLOCK_LEN]
        seek = initial_seek + i
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        output = xor(output, block_output)
    return output
```

In other words:

- Split the message into 64-byte blocks, with the last block possibly short.
- Compute the keyed BLAKE3 hash of each block _separately_.
- For each output, seek to the position in the output stream corresponding to
  the `initial_seek` plus the message position. Take 16 bytes.
- XOR all the 16-byte tags together to form the output.

The XOR structure makes it possible to compute all of the blocks in parallel.
The regular BLAKE3 tree structure is also parallelizable, but only at a
granularity of 1 KiB chunks. `universal_hash` is parallelizable over 64-byte
blocks.

The security properties of this function are intended to be similar to those of
GHASH from AES-GCM or (unencrypted) Poly1305 from ChaCha20-Poly1305.
["Universal hash"](https://en.wikipedia.org/wiki/Universal_hashing) is a
somewhat academic term, but suffice it to say that these are _much weaker_ than
a regular keyed hash like BLAKE3 or HMAC. They are about as hazmat as hazmat
gets.

We use the `initial_seek` parameter for domain separation below.

### Encrypt

```python
MSG_SEEK = 2**63
AAD_SEEK = 2**63 + 2**62

def encrypt(key, nonce, aad, plaintext):
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN)
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash(key, ciphertext_msg, MSG_SEEK)
    aad_tag = universal_hash(key, aad, AAD_SEEK)
    tag = xor(stream[len(plaintext) :], xor(msg_tag, aad_tag))
    return ciphertext_msg + tag
```

The BLAKE3 XOF supports up to 2<sup>64</sup>-1 output bytes. We divide the
output space into three parts, with the stream cipher starting at offset 0, the
message authenticator starting at offset 2<sup>63</sup>, and the associated
data authenticator starting at offset 2<sup>63</sup>+2<sup>62</sup>. We
generate 16 extra bytes of stream cipher output past the message length, and we
use those extra bytes to mask the combined authentication tag.

### Decrypt

```python
def decrypt(key, nonce, aad, ciphertext):
    plaintext_len = len(ciphertext) - TAG_LEN
    ciphertext_msg = ciphertext[:plaintext_len]
    stream = blake3(nonce, key=key).digest(length=plaintext_len + TAG_LEN)
    msg_tag = universal_hash(key, ciphertext_msg, MSG_SEEK)
    aad_tag = universal_hash(key, aad, AAD_SEEK)
    expected_tag = xor(stream[plaintext_len:], xor(msg_tag, aad_tag))
    if not compare_digest(expected_tag, ciphertext[plaintext_len:]):
        raise ValueError("invalid ciphertext")
    return xor(ciphertext_msg, stream[:plaintext_len])
```
