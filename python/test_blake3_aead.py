from blake3 import blake3
from blake3_aead import (
    encrypt,
    decrypt,
    universal_hash,
    xor,
    BLOCK_LEN,
    TAG_LEN,
    MAX_MSG_LEN,
    MAX_NONCE_LEN,
    MSG_AUTH_SEEK,
    AAD_AUTH_SEEK,
    STREAM_SEEK,
)
from tempfile import NamedTemporaryFile
import secrets
import subprocess


def universal_hash_b3sum(
    key: bytes,
    message: bytes,
    initial_seek: int,
) -> bytes:
    assert initial_seek % BLOCK_LEN == 0
    result = bytes(TAG_LEN)
    for i in range(0, len(message), BLOCK_LEN):
        with NamedTemporaryFile() as f:
            block = message[i : i + BLOCK_LEN]
            f.write(block)
            f.flush()
            block_output = subprocess.run(
                [
                    "b3sum",
                    f.name,
                    "--keyed",
                    "--raw",
                    "--length",
                    str(TAG_LEN),
                    "--seek",
                    str(initial_seek + i),
                ],
                input=key,
                stdout=subprocess.PIPE,
            ).stdout
            result = xor(result, block_output)
    return result


def test_universal_hash_implementations_agree() -> None:
    for length in [0, 1, 64, 65, 128, 1000]:
        key = secrets.token_bytes(blake3.key_size)
        message = secrets.token_bytes(length)
        regular_result = universal_hash(key, message, 99 * BLOCK_LEN)
        cli_result = universal_hash_b3sum(key, message, 99 * BLOCK_LEN)
        assert regular_result == cli_result, f"length {length}"


def encrypt_b3sum(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
) -> bytes:
    assert len(nonce) <= MAX_NONCE_LEN
    assert len(aad) <= MAX_MSG_LEN
    assert len(plaintext) <= MAX_MSG_LEN
    with NamedTemporaryFile() as f:
        f.write(nonce)
        f.flush()
        stream = subprocess.run(
            [
                "b3sum",
                f.name,
                "--keyed",
                "--raw",
                "--length",
                str(len(plaintext) + TAG_LEN),
                "--seek",
                str(STREAM_SEEK),
            ],
            input=key,
            stdout=subprocess.PIPE,
        ).stdout
    ciphertext_msg = xor(plaintext, stream[: len(plaintext)])
    msg_tag = universal_hash_b3sum(key, ciphertext_msg, MSG_AUTH_SEEK)
    aad_tag = universal_hash_b3sum(key, aad, AAD_AUTH_SEEK)
    tag = xor(stream[len(plaintext) :], xor(msg_tag, aad_tag))
    return ciphertext_msg + tag


def test_encrypt_implementations_agree() -> None:
    for length in [0, 1, 64, 65, 128, 1000]:
        key = secrets.token_bytes(blake3.key_size)
        nonce = secrets.token_bytes(length)[:MAX_NONCE_LEN]
        message = secrets.token_bytes(length)
        aad = secrets.token_bytes(length)
        regular_result = encrypt(key, nonce, aad, message)
        cli_result = encrypt_b3sum(key, nonce, aad, message)
        assert regular_result == cli_result, f"length {length}"


def test_xor_parts() -> None:
    key = secrets.token_bytes(blake3.key_size)
    message = secrets.token_bytes(1000)
    left_len = 512  # must be a multiple of 64
    left_tag = universal_hash(key, message[:left_len], 0)
    right_tag = universal_hash(key, message[left_len:], left_len)
    assert universal_hash(key, message, 0) == xor(left_tag, right_tag)


def test_aead_round_trip() -> None:
    key = secrets.token_bytes(blake3.key_size)
    nonce = secrets.token_bytes(12)
    for msg_len in [0, 1, 64, 1000]:
        for aad_len in [0, 1, 64, 1000]:
            message = secrets.token_bytes(msg_len)
            aad = secrets.token_bytes(aad_len)
            ciphertext = encrypt(key, nonce, aad, message)
            assert len(ciphertext) == len(message) + TAG_LEN
            decrypted = decrypt(key, nonce, aad, ciphertext)
            assert message == decrypted

            # Test decryption failure.
            bad_aad = secrets.token_bytes(32)
            try:
                decrypt(key, nonce, ciphertext, bad_aad)
            except ValueError:
                pass
            else:
                assert False, "changing the AAD should fail decryption"
