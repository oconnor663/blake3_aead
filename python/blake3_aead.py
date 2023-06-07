from blake3 import blake3
import subprocess
from tempfile import NamedTemporaryFile


def xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def blake3_universal_hash(
    one_time_key: bytes, message: bytes, counter: int = 0
) -> bytes:
    result = bytearray(blake3.block_size)
    position = 0
    while position == 0 or position < len(message):
        block_output = blake3(
            message[position : position + blake3.block_size],
            key=one_time_key,
        ).digest(
            seek=blake3.block_size * counter + position,
            length=64,
        )
        result = xor(result, block_output)
        position += blake3.block_size
    return result


def blake3_universal_hash_cli(
    one_time_key: bytes, message: bytes, counter: int = 0
) -> bytes:
    result = bytearray(blake3.block_size)
    position = 0
    while position == 0 or position < len(message):
        with NamedTemporaryFile() as f:
            f.write(message[position : position + blake3.block_size])
            f.flush()
            seek = blake3.block_size * counter + position
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
            result = xor(result, block_output)
            position += blake3.block_size
    return result


def test_implementations_agree():
    from secrets import token_bytes

    for i in range(100):
        key = token_bytes(blake3.key_size)
        message = token_bytes(i)
        regular_result = blake3_universal_hash(key, message)
        cli_result = blake3_universal_hash_cli(key, message)
        assert regular_result == cli_result
