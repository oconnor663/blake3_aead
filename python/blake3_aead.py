from blake3 import blake3
from hmac import compare_digest

TAG_LEN = 16
BLOCK_LEN = blake3.block_size
MAX_NONCE_LEN = BLOCK_LEN

MSG_AUTH_SEEK = 0
AAD_AUTH_SEEK = 2**62
STREAM_SEEK = 2**63


def xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def universal_hash(
    key: bytes,
    message: bytes,
    initial_seek: int,
) -> bytes:
    assert initial_seek % BLOCK_LEN == 0
    output = bytes(TAG_LEN)
    for block_start in range(0, len(message), BLOCK_LEN):
        block = message[block_start : block_start + BLOCK_LEN]
        seek = initial_seek + block_start
        block_output = blake3(block, key=key).digest(length=TAG_LEN, seek=seek)
        output = xor(output, block_output)
    return output


def encrypt(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
) -> bytes:
    assert len(nonce) <= MAX_NONCE_LEN
    stream = blake3(nonce, key=key).digest(length=len(plaintext) + TAG_LEN, seek=STREAM_SEEK)
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash(key, ciphertext_msg, MSG_AUTH_SEEK)
    aad_tag = universal_hash(key, aad, AAD_AUTH_SEEK)
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
    stream = blake3(nonce, key=key).digest(length=len(ciphertext), seek=STREAM_SEEK)
    msg_tag = universal_hash(key, ciphertext_msg, MSG_AUTH_SEEK)
    aad_tag = universal_hash(key, aad, AAD_AUTH_SEEK)
    expected_tag = xor(stream[plaintext_len:], xor(msg_tag, aad_tag))
    if not compare_digest(expected_tag, ciphertext[plaintext_len:]):
        raise ValueError("invalid ciphertext")
    return xor(ciphertext_msg, stream[:plaintext_len])
