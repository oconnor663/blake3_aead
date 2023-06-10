from blake3 import blake3
from hmac import compare_digest

TAG_LEN = 16
BLOCK_LEN = blake3.block_size

# Supporting nonces larger than 64 bytes would be trivial for any
# implementation that's built on a BLAKE3 library. However, not all
# implementations need the full hash function. A compact implementation might
# prefer to work directly with the compression function and omit the tree
# hashing parts. Restricting nonces to 64 bytes allows for these compact
# implementations, and 64 bytes is already generous. For comparison, the
# extended nonces in XSalsa and XChaCha are 24 bytes.
MAX_NONCE_LEN = BLOCK_LEN

MSG_HASH_SEEK = 1 << 63
MSG_HASH_COUNTER = MSG_HASH_SEEK // BLOCK_LEN
AAD_HASH_SEEK = (1 << 63) + (1 << 62)
AAD_HASH_COUNTER = AAD_HASH_SEEK // BLOCK_LEN


def xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def universal_hash(
    key: bytes,
    message: bytes,
    initial_block_counter: int,
) -> bytes:
    result = bytes(TAG_LEN)
    for i in range(0, len(message), BLOCK_LEN):
        block = message[i : i + BLOCK_LEN]
        seek = BLOCK_LEN * initial_block_counter + i
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        result = xor(result, block_output)
    return result


def encrypt(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
) -> bytes:
    assert len(nonce) <= MAX_NONCE_LEN
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN)
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash(key, ciphertext_msg, MSG_HASH_COUNTER)
    aad_tag = universal_hash(key, aad, AAD_HASH_COUNTER)
    tag = xor(stream[len(plaintext) :], xor(msg_tag, aad_tag))
    return ciphertext_msg + tag


def decrypt(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    assert len(nonce) <= MAX_NONCE_LEN
    plaintext_len = len(ciphertext) - TAG_LEN
    ciphertext_msg = ciphertext[:plaintext_len]
    tag = ciphertext[plaintext_len:]
    stream = blake3(nonce, key=key).digest(length=plaintext_len + TAG_LEN)
    msg_tag = universal_hash(key, ciphertext_msg, MSG_HASH_COUNTER)
    aad_tag = universal_hash(key, aad, AAD_HASH_COUNTER)
    expected_tag = xor(stream[plaintext_len:], xor(msg_tag, aad_tag))
    if not compare_digest(expected_tag, tag):
        raise ValueError("invalid ciphertext")
    return xor(ciphertext_msg, stream[:plaintext_len])
