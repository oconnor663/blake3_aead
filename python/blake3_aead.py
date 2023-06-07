from blake3 import blake3


def _xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def blake3_universal_hash(
    one_time_key: bytes, message: bytes, *, block_counter: int = 0
) -> bytes:
    """EXPERIMENTAL! This is a low-level, "hazmat" building block for AEAD
    ciphers. Applications that need to authenticate messages should prefer the
    standard BLAKE3 keyed hash.

    blake3_universal_hash is spiritually similar to GCM/GHASH and Poly1305, and
    in NaCl/libsodium terms we could call this blake3_onetimeauth. Compared to
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
            key=one_time_key,
        ).digest(
            seek=blake3.block_size * block_counter + position,
            length=64,
        )
        result = _xor(result, block_output)
        position += blake3.block_size
    return result
