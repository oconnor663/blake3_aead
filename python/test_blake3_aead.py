from blake3 import blake3
from blake3_aead import blake3_universal_hash, _xor
from tempfile import NamedTemporaryFile
import secrets
import subprocess


def blake3_universal_hash_cli(
    one_time_key: bytes, message: bytes, *, block_counter: int = 0
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
        regular_result = blake3_universal_hash(key, message)
        cli_result = blake3_universal_hash_cli(key, message)
        assert regular_result == cli_result, f"length {length}"


def test_xor_parts():
    key = secrets.token_bytes(blake3.key_size)
    message = secrets.token_bytes(1000)
    left_len = 512  # must be a multiple of 64
    left_part = message[:512]
    right_part = message[512:]
    left_hash = blake3_universal_hash(key, left_part)
    right_hash = blake3_universal_hash(key, right_part, block_counter=left_len // 64)
    assert blake3_universal_hash_cli(key, message) == _xor(left_hash, right_hash)
