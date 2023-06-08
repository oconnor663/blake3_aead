from blake3 import blake3
from hmac import compare_digest

TAG_LEN = 16
MSG_HASH_SEEK = 1 << 63
MSG_HASH_COUNTER = MSG_HASH_SEEK // blake3.block_size
AAD_HASH_SEEK = (1 << 63) + (1 << 62)
AAD_HASH_COUNTER = AAD_HASH_SEEK // blake3.block_size


def _xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def blake3_universal_hash(
    key: bytes,
    message: bytes,
    block_counter: int,
) -> bytes:
    """EXPERIMENTAL! This is a low-level, "hazmat" building block for AEAD
    ciphers. Applications that need to authenticate messages should prefer the
    standard BLAKE3 keyed hash.

    blake3_universal_hash is spiritually similar to GCM/GHASH and Poly1305, and
    in NaCl/libsodium terms we could call this blake3_onetimeauth. Security is
    generally lost if you publish two outputs using the same key. Compared to
    standard keyed BLAKE3, blake3_universal_hash sacrifices collision
    resistance, second-preimage resistance, key reuse, and extendable output
    for better parallelism at short message lengths. The 64-byte return value
    is intended to be truncated according to the required security level.

    The optional block_counter argument can be used hash messages in parts, by
    using the same key for each part and setting the counter to each part's
    starting block index (i.e. byte offset / 64). The parts must be split at
    64-byte block boundaries. The XOR of the hashes of the parts gives the hash
    of the whole message."""
    result = bytearray(blake3.block_size)
    position = 0
    while position == 0 or position < len(message):
        block_output = blake3(
            message[position : position + blake3.block_size],
            key=key,
        ).digest(
            seek=blake3.block_size * block_counter + position,
            length=64,
        )
        result = _xor(result, block_output)
        position += blake3.block_size
    return result


def blake3_aead_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN)
    masked_plaintext = _xor(plaintext, stream[: len(plaintext)])
    tag = stream[len(plaintext) :]
    if plaintext:
        msg_tag = blake3_universal_hash(key, masked_plaintext, MSG_HASH_COUNTER)
        tag = _xor(tag, msg_tag[:TAG_LEN])
    if aad:
        aad_tag = blake3_universal_hash(key, aad, AAD_HASH_COUNTER)
        tag = _xor(tag, aad_tag[:TAG_LEN])
    return masked_plaintext + tag


def blake3_aead_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    plaintext_len = len(ciphertext) - TAG_LEN
    masked_plaintext = ciphertext[:plaintext_len]
    tag = ciphertext[plaintext_len:]
    stream = blake3(nonce, key=key).digest(length=plaintext_len + TAG_LEN)
    if plaintext_len:
        msg_tag = blake3_universal_hash(key, masked_plaintext, MSG_HASH_COUNTER)
        tag = _xor(tag, msg_tag[:TAG_LEN])
    if aad:
        aad_tag = blake3_universal_hash(key, aad, AAD_HASH_COUNTER)
        tag = _xor(tag, aad_tag[:TAG_LEN])
    if not compare_digest(tag, stream[plaintext_len:]):
        raise ValueError("invalid ciphertext")
    return _xor(masked_plaintext, stream[:plaintext_len])
