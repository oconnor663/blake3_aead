from blake3 import blake3
from blake3_aead import (
    encrypt,
    decrypt,
    universal_hash,
    _xor,
    TAG_LEN,
)
from tempfile import NamedTemporaryFile
import secrets
import subprocess


def universal_hash_cli(
    one_time_key: bytes,
    message: bytes,
    block_counter: int,
) -> bytes:
    result = bytearray(blake3.block_size)
    position = 0
    while position == 0 or position < len(message):
        with NamedTemporaryFile() as f:
            f.write(message[position : position + blake3.block_size])
            f.flush()
            seek = blake3.block_size * block_counter + position
            block_output = subprocess.run(
                [
                    "b3sum",
                    f.name,
                    "--keyed",
                    "--raw",
                    "--length",
                    str(blake3.block_size),
                    "--seek",
                    str(seek),
                ],
                input=one_time_key,
                stdout=subprocess.PIPE,
            ).stdout
            result = _xor(result, block_output)
            position += blake3.block_size
    return result


def test_implementations_agree():
    for length in [0, 1, 64, 65, 128, 1000]:
        key = secrets.token_bytes(blake3.key_size)
        message = secrets.token_bytes(length)
        regular_result = universal_hash(key, message, 42)
        cli_result = universal_hash_cli(key, message, 42)
        assert regular_result == cli_result, f"length {length}"


def test_xor_parts():
    key = secrets.token_bytes(blake3.key_size)
    message = secrets.token_bytes(1000)
    left_len = 512  # must be a multiple of 64
    left_part = message[:512]
    right_part = message[512:]
    left_hash = universal_hash(key, left_part, 0)
    right_hash = universal_hash(key, right_part, left_len // 64)
    assert universal_hash(key, message, 0) == _xor(left_hash, right_hash)


def test_aead_round_trip():
    key = secrets.token_bytes(blake3.key_size)
    nonce = secrets.token_bytes(12)
    for msg_len in [0, 1, 64, 1000]:
        for aad_len in [0, 1, 64, 1000]:
            message = secrets.token_bytes(msg_len)
            aad = secrets.token_bytes(aad_len)
            ciphertext = encrypt(key, nonce, message, aad)
            assert len(ciphertext) == len(message) + TAG_LEN
            decrypted = decrypt(key, nonce, ciphertext, aad)
            assert message == decrypted

            # Test decryption failure.
            bad_aad = secrets.token_bytes(32)
            try:
                decrypt(key, nonce, ciphertext, bad_aad)
            except ValueError:
                pass
            else:
                assert False, "changing the AAD should fail decryption"
