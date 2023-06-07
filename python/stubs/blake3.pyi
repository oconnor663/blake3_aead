class blake3:
    name: str
    digest_size: int
    block_size: int
    key_size: int
    AUTO: int
    def __init__(
        self,
        data: bytes,
        /,
        *,
        key: bytes = ...,
        derive_key_context: str = ...,
        max_threads: int = ...,
        usedforsecurity: bool = ...,
    ): ...
    def update(self, data: bytes): ...
    def copy(self, data: bytes) -> blake3: ...
    def reset(self): ...
    def digest(self, length: int = ..., seek: int = ...) -> bytes: ...
    def hexdigest(self, length: int = ..., seek: int = ...) -> bytes: ...
