from blake3 import blake3
from blake3_aead import (
    encrypt,
    decrypt,
    universal_hash,
    xor,
    BLOCK_LEN,
    TAG_LEN,
)
from tempfile import NamedTemporaryFile
import secrets
import subprocess


def universal_hash_cli(
    one_time_key: bytes,
    message: bytes,
    initial_seek: int,
) -> bytes:
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
                input=one_time_key,
                stdout=subprocess.PIPE,
            ).stdout
            result = xor(result, block_output)
    return result


def test_implementations_agree():
    for length in [0, 1, 64, 65, 128, 1000]:
        key = secrets.token_bytes(blake3.key_size)
        message = secrets.token_bytes(length)
        regular_result = universal_hash(key, message, 99 * BLOCK_LEN)
        cli_result = universal_hash_cli(key, message, 99 * BLOCK_LEN)
        assert regular_result == cli_result, f"length {length}"


def test_xor_parts():
    key = secrets.token_bytes(blake3.key_size)
    message = secrets.token_bytes(1000)
    left_len = 512  # must be a multiple of 64
    left_tag = universal_hash(key, message[:left_len], 0)
    right_tag = universal_hash(key, message[left_len:], left_len)
    assert universal_hash(key, message, 0) == xor(left_tag, right_tag)


def test_aead_round_trip():
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
