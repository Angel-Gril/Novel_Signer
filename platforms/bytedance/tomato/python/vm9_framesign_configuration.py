"""FrameSign's observed 263-byte configuration transform after RC4.

The RC4 output and twelve reduction bytes are explicit inputs. This does not
generate the upstream cipher input, RC4 key, reduction material or lookup key.
"""
from __future__ import annotations


def reverse_xor_configuration(stream_output: bytes, reduction_bytes: bytes) -> bytes:
    """Reverse all 263 bytes and XOR each with the zero-initialized reduction."""
    if type(stream_output) is not bytes or len(stream_output) != 263:
        raise ValueError('configuration stream output must be exactly 263 bytes')
    if type(reduction_bytes) is not bytes or len(reduction_bytes) != 12:
        raise ValueError('configuration reduction must be exactly twelve bytes')
    mask = 0
    for value in reduction_bytes:
        mask ^= value
    return bytes(value ^ mask for value in reversed(stream_output))
