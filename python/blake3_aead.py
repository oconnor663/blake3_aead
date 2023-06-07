from blake3 import blake3


def _xor(a: bytes, b: bytes):
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
        result = _xor(result, block_output)
        position += blake3.block_size
    return result
