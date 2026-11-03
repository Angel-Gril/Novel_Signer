"""Sample-verified FrameSign block stage; all unrecovered inputs stay explicit.

This does not generate keys, feedback, allocator addresses or a signature.
Only the fixed 88-byte pre-block profile was compared with the native target.
"""
from __future__ import annotations

MASK32 = (1 << 32) - 1
DELTA = 0x9E3779B9


def xtea_cbc(data: bytes, key: bytes, feedback: bytes) -> bytes:
    """32 rounds, big-endian data words, little-endian key words; no padding."""
    if type(data) is not bytes or not data or len(data) % 8 or len(data) > 0x100000:
        raise ValueError("block data must be nonempty, bounded and aligned to eight bytes")
    if type(key) is not bytes or len(key) != 16:
        raise ValueError("block key must contain sixteen bytes")
    if type(feedback) is not bytes or len(feedback) != 8:
        raise ValueError("block feedback must contain eight bytes")
    words = tuple(int.from_bytes(key[i:i + 4], "little") for i in range(0, 16, 4))
    output = bytearray()
    for start in range(0, len(data), 8):
        mixed = bytes(a ^ b for a, b in zip(data[start:start + 8], feedback))
        left = int.from_bytes(mixed[:4], "big")
        right = int.from_bytes(mixed[4:], "big")
        total = 0
        for _ in range(32):
            left = (left + ((((right << 4) ^ (right >> 5)) + right)
                            ^ (total + words[total & 3]))) & MASK32
            total = (total + DELTA) & MASK32
            right = (right + ((((left << 4) ^ (left >> 5)) + left)
                              ^ (total + words[(total >> 11) & 3]))) & MASK32
        feedback = left.to_bytes(4, "big") + right.to_bytes(4, "big")
        output.extend(feedback)
    return bytes(output)


def observed_plaintext(preblock: bytes, key: bytes, feedback: bytes,
                       feedback_address: int, prefix_xor: int) -> bytes:
    """Rebuild this profile's 1 + 88 + 4 bytes from explicitly supplied inputs."""
    if type(preblock) is not bytes or len(preblock) != 88:
        raise ValueError("the observed pre-block profile contains eighty-eight bytes")
    if type(feedback_address) is not int or not 0 < feedback_address < 1 << 64:
        raise ValueError("feedback address must be a nonzero uint64")
    if type(prefix_xor) is not int or not 0 <= prefix_xor <= 0xFFFF:
        raise ValueError("prefix XOR operand must be a uint16")
    ciphertext = xtea_cbc(preblock, key, feedback)
    prefix = bytes([(ciphertext[0] ^ prefix_xor) & 0xFF])
    suffix = (feedback_address & MASK32).to_bytes(4, "little")
    return prefix + ciphertext + suffix
