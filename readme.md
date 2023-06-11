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
  2<sup>62</sup>-1 bytes respectively
- The message and associated data can be processed in in parallel, in one pass
  each, without knowing their lengths in advance.
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

Aside: All of these drawbacks are in common with AES-GCM and ChaCha20-Poly1305.
These TLS-oriented ciphers prioritize bytes on the wire and short-message
performance above all else, and in my opinion that makes them "hazmat" building
blocks, for experts only. BLAKE3-AEAD aims for the same use case and makes the
same tradeoffs. For a more general-purpose design with fewer sharp edges, see
[Bessie](https://github.com/oconnor663/bessie).

## Design

### Some BLAKE3 background

This design relies on two features of BLAKE3 in particular. First, BLAKE3 has a
built-in keyed mode. It works by substituting the caller's key in place of the
standard IV, and it doesn't require any extra compressions.

Second, BLAKE3 supports extendable output. Extended output blocks are produced
by incrementing the compression function's internal `t` parameter, which allows
for computing blocks in parallel or seeking to any point in the output stream.
This makes the extended output a natural stream cipher, and it also lets us use
seeking for domain separation, similar to the tweak in a tweakable block
cipher.

### Universal hash

The Python code samples in this document are excerpted from
[`blake3_aead.py`](python/blake3_aead.py).

```python
TAG_LEN = 16
BLOCK_LEN = 64

def universal_hash(key, message, initial_seek):
    output = bytes(TAG_LEN)
    for block_start in range(0, len(message), BLOCK_LEN):
        block = message[block_start : block_start + BLOCK_LEN]
        seek = initial_seek + block_start
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        output = xor(output, block_output)
    return output
```

In other words:

- Split the message into 64-byte blocks, with the last block possibly short.
- Compute the keyed BLAKE3 hash of each block separately.
- For each block output, seek to the position in the output stream equal to
  `initial_seek` plus the message position. Take 16 bytes.
- XOR all the 16-byte tags together to form the output.

The XOR structure makes it possible to compute all of the blocks in parallel.
The regular BLAKE3 tree structure is also parallelizable, but only at a
granularity of 1 KiB chunks, while `universal_hash` is parallelizable over
64-byte blocks. This is important for short-message performance.

The security properties of this function are intended to be similar to those of
GHASH from AES-GCM or (unmasked) Poly1305 from ChaCha20-Poly1305. ["Universal
hash"](https://en.wikipedia.org/wiki/Universal_hashing) is a somewhat academic
term, but suffice it to say that these are _much weaker_ than a regular keyed
hash like BLAKE3 or HMAC. They're as hazmat as hazmat gets.

The `initial_seek` parameter is used for domain separation below.

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

The BLAKE3 XOF supports up to 2<sup>64</sup>-1 output bytes. The output space
is divided into three parts, with the key stream starting at offset 0, the
message authenticator starting at offset 2<sup>63</sup>, and the associated
data authenticator starting at offset 2<sup>63</sup>+2<sup>62</sup>. The stream
cipher produces 16 extra bytes of output beyond the message length, and those
extra bytes are used to mask the combined authentication tag.

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

## Rationales

### Authenticator structure

Broadly speaking there are two options for constructing the authenticator:

- Compute it with the long-term key and mask it with the key stream (what this
  design does).
- Compute it with a nonce-derived key and publish it unmasked.

Deriving a subkey would probably always incur a call to the compression
function, while masking is sometimes free, if the final block of the message
happens to be 48 bytes or less. Note that if you use a tag mask, you don't need
it until the end of the encryption process, so it's natural to get it from the
tail of the stream. But if you use derived subkeys, you need them at the start,
and using the tail of the stream would be awkward.

"Add 16 bytes to the end of the stream" is also easier for the implementation
to parallelize than "reserve a block at the front of the stream". Ideally you
get the whole stream from one function call, but then that call needs output
space to write the stream bytes. The most natural place is the caller's output
buffer, especially if you can XOR the stream directly over the plaintext. That
buffer already needs 16 bytes at the end reserved for the tag, so using those
bytes as scratch space is free. But asking the caller for a block of scratch
space at the front [would be awkward](https://nacl.cr.yp.to/secretbox.html).

Note that it's not safe to use `universal_hash` unmasked as-is, because its
output is all-zero when its input is empty, regardless of the key. We could
change that by adjusting the definition so that the empty input is still
considered one block. On the other hand, it's nice not to incur a call to the
compression function for the AAD when it's empty.

### Misuse resistance

It could've been nice to incorporate the MAC of the plaintext into the key
stream, to provide some resistance against nonce reuse. But that has
performance downsides: Encryption would require two passes over the input, and
the recipient would have to do all the work of decryption before rejecting a
bad packet.

### Seek constants

We could've divided the XOF output space into three approximately equal parts,
rather than the current arrangement where half of it is allocated to the key
stream. However, increasing the maximum message size from 2<sup>62</sup> bytes
to ~2<sup>62.4</sup> bytes has almost no practical value, and it's nicer to
keep the `MSG_SEEK` and `AAD_SEEK` constants simple.

### Nonce length

Supporting nonces larger than 64 bytes would be trivial for any implementation
that's built with a BLAKE3 library, and in fact the code samples above already
do (because some asserts have been omitted). However, not all implementations
will want to carry along the full BLAKE3 hash function. A compact
implementation might prefer to work directly with the compression function and
omit the tree hashing parts. Restricting nonces to 64 bytes allows for these
compact implementations, and 64 bytes is already quite generous. For
comparison, the extended nonces in XSalsa and XChaCha are only 24 bytes.
