"""Sample-verified FrameSign pre-block composition from explicit inputs.

The component, allocator address and seed operands are explicit inputs. This
model covers the observed 76-byte component and 88-byte block profile.
"""
from __future__ import annotations


def crc16_xmodem(data: bytes) -> int:
    """Polynomial 0x1021, initial zero, non-reflected, with no final XOR."""
    if type(data) is not bytes or len(data) > 0x100000:
        raise ValueError("CRC input must be bounded bytes")
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


def observed_preblock(component: bytes, allocation_address: int,
                      seed_mask: int, seed_right: int) -> bytes:
    """Derive the seed/header, then append CRC16, component and zero padding."""
    if type(component) is not bytes or len(component) != 76:
        raise ValueError("the observed component must contain seventy-six bytes")
    if type(allocation_address) is not int or not 0 < allocation_address < 1 << 64:
        raise ValueError("allocation address must be a nonzero uint64")
    if type(seed_mask) is not int or not 0 <= seed_mask <= 0xFFFF:
        raise ValueError("seed mask must be a uint16")
    if type(seed_right) is not int or not 0 <= seed_right < 1 << 64:
        raise ValueError("seed right operand must be a uint64")
    seed = (((allocation_address & seed_mask) & 0xFFFF) | seed_right) & 255
    retained_header = (allocation_address >> 16) & 255
    return (bytes([seed]) + crc16_xmodem(component).to_bytes(2, "big")
            + bytes([retained_header]) + component + bytes(8))
