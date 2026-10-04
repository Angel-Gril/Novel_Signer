"""Guest-table-driven cipher schedules and observed block dispatch.

Only caller pages and matching loaded ELF tables drive these functions.
No native key/context output or captured payload is supplied to the model.
"""
from __future__ import annotations

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
import vm9_objects as objects

MASK32 = 0xFFFFFFFF


def _u32(pages, address):
    return int.from_bytes(_read_span(pages, address, 4), "little")


def _put32(pages, address, value):
    _write_span(pages, address, (value & MASK32).to_bytes(4, "little"))


def _table(pages, base, offset, index):
    return _u32(pages, objects._image_address(base, offset) + index * 4)


def _sub_word(pages, base, word, *, rotate):
    shifts = (16, 8, 0, 24) if rotate else (24, 16, 8, 0)
    result = 0
    for offset, shift in zip((0x91750, 0x91B50, 0x91F50, 0x92350), shifts):
        result ^= _table(pages, base, offset, (word >> shift) & 255)
    return result


def _inverse_mix_word(pages, base, word):
    result = 0
    for offset, shift in zip((0x92778, 0x92B78, 0x92F78, 0x93378), (24, 16, 8, 0)):
        result ^= _table(pages, base, offset, (word >> shift) & 255)
    return result


def construct_cipher_schedule(pages, *, context_address: int, key_address: int,
                              key_size: int, image_base: int) -> int:
    """Model +0x241e9c; populate enc/dec words and rounds, return 0 or -1.

    Invalid u32 sizes still write rounds and the first four key words before
    returning -1. Key words are read/stored sequentially, preserving aliases.
    A successful context spans 0x1e8 bytes; untouched key slots stay intact.
    Unknown mapped inputs reject transactionally; native partial status does
    not cause rollback. No table is replaced by a host crypto constant.
    """
    if not isinstance(key_size, int) or not 0 <= key_size <= MASK32:
        raise ValueError("cipher key size must be a u32")
    transaction = _PageTransaction(pages)
    rounds = (((key_size >> 2) & 0x3FFFFFFE) + 6) & MASK32
    _write_span(transaction, context_address + 0x1E0, objects._word(rounds))
    for i in range(4):
        _put32(transaction, context_address + i * 4,
               int.from_bytes(_read_span(transaction, key_address + i * 4, 4), "big"))
    if key_size not in (16, 24, 32):
        transaction.commit()
        return -1
    words = key_size // 4
    for i in range(4, words):
        _put32(transaction, context_address + i * 4,
               int.from_bytes(_read_span(transaction, key_address + i * 4, 4), "big"))
    for i in range(words, 4 * (rounds + 1)):
        prior = _u32(transaction, context_address + (i - 1) * 4)
        if i % words == 0:
            prior = _sub_word(transaction, image_base, prior, rotate=True)
            prior ^= _table(transaction, image_base, 0x92750, i // words - 1)
        elif words == 8 and i % words == 4:
            prior = _sub_word(transaction, image_base, prior, rotate=False)
        _put32(transaction, context_address + i * 4,
               _u32(transaction, context_address + (i - words) * 4) ^ prior)
    for round_index in range(rounds + 1):
        for i in range(4):
            word = _u32(transaction, context_address + (rounds - round_index) * 16 + i * 4)
            if 0 < round_index < rounds:
                word = _inverse_mix_word(transaction, image_base, word)
            _put32(transaction, context_address + 0xF0 + round_index * 16 + i * 4, word)
    transaction.commit()
    return 0


def _cipher_block(pages, context, source, output, base, *, decrypt):
    rounds = int.from_bytes(_read_span(pages, context + 0x1E0, 8), "little")
    if rounds not in range(2, 15, 2):
        raise RefillUnsupported("unrecovered cipher round count")
    payload = _read_span(pages, source, 16)
    schedule = context + (0xF0 if decrypt else 0)
    state = [int.from_bytes(payload[i * 4:i * 4 + 4], "big") ^ _u32(pages, schedule + i * 4)
             for i in range(4)]
    table_start = 0x94778 if decrypt else 0x93778
    direction = -1 if decrypt else 1
    for round_index in range(1, rounds):
        next_state = []
        for i in range(4):
            word = _u32(pages, schedule + round_index * 16 + i * 4)
            for j, shift in enumerate((24, 16, 8, 0)):
                index = (state[(i + direction * j) % 4] >> shift) & 255
                word ^= _table(pages, base, table_start + j * 0x400, index)
            next_state.append(word)
        state = next_state
    final = []
    for i in range(4):
        word = _u32(pages, schedule + rounds * 16 + i * 4)
        for j, shift in enumerate((24, 16, 8, 0)):
            index = (state[(i + direction * j) % 4] >> shift) & 255
            if decrypt:
                byte = _read_span(pages, objects._image_address(base, 0x95778) + index * 4 + shift // 8, 1)[0]
                word ^= byte << shift
            else:
                word ^= _table(pages, base, (0x91750, 0x91B50, 0x91F50, 0x92350)[j], index)
        final.append(word.to_bytes(4, "big"))
    _write_span(pages, output, b"".join(final))


def encrypt_cipher_block(pages, *, context_address: int, source_address: int,
                         output_address: int, image_base: int) -> None:
    """Model +0x2422ec's guest-table encryption, including in-place input."""
    transaction = _PageTransaction(pages)
    _cipher_block(transaction, context_address, source_address, output_address, image_base, decrypt=False)
    transaction.commit()


def decrypt_cipher_block(pages, *, context_address: int, source_address: int,
                         output_address: int, image_base: int) -> None:
    """Model +0x242640's guest-table decryption; native X0 is unspecified."""
    transaction = _PageTransaction(pages)
    _cipher_block(transaction, context_address, source_address, output_address, image_base, decrypt=True)
    transaction.commit()


def decrypt_cipher_cbc(pages, *, context_address: int, source_address: int,
                       output_address: int, length: int, entry_stack_address: int,
                       image_base: int, max_bytes: int = 0x100000) -> int:
    """Model +0x242b18 with IV at context+0x1e8; invalid multiples return -1.

    Native saves old IV to entry SP-0x60, loads the next ciphertext into IV,
    decrypts it and XORs saved IV byte by byte. Caller stack is explicit so
    aliases with this scratch are driven by memory rather than cached bytes.
    """
    if not isinstance(length, int) or not 0 <= length <= MASK32:
        raise ValueError("cipher length must be a u32")
    objects._string_bound(max_bytes)
    if length & 15:
        return -1
    if length > max_bytes:
        raise RefillUnsupported("cipher CBC exceeds the explicit byte bound")
    transaction = _PageTransaction(pages)
    for offset in range(0, length, 16):
        iv = context_address + 0x1E8
        saved = entry_stack_address - 0x60
        old_iv = _read_span(transaction, iv, 16)
        payload = _read_span(transaction, source_address + offset, 16)
        _write_span(transaction, saved, old_iv)
        _write_span(transaction, iv, payload)
        _cipher_block(transaction, context_address, iv, output_address + offset, image_base, decrypt=True)
        for i in range(16):
            a = _read_span(transaction, saved + i, 1)[0]
            b = _read_span(transaction, output_address + offset + i, 1)[0]
            _write_span(transaction, output_address + offset + i, bytes([a ^ b]))
    transaction.commit()
    return 0


def process_cipher_blocks(pages, *, mode_descriptor_address: int, context_address: int,
                          source_address: int, output_address: int, length: int,
                          entry_stack_address: int, image_base: int,
                          max_bytes: int = 0x100000) -> int:
    """Model supported +0x25ab1c branches using its guest jump table.

    ECB processes complete 16-byte chunks even for a partial declared length.
    CBC rejects partial lengths. Native modes >3 return 0 unchanged. Other
    known dispatch targets (stream branches) reject until separately recovered.
    """
    if not isinstance(length, int) or not 0 <= length <= MASK32:
        raise ValueError("cipher length must be a u32")
    objects._string_bound(max_bytes)
    transaction = _PageTransaction(pages)
    pointer = int.from_bytes(_read_span(transaction, mode_descriptor_address, 8), "little")
    mode = _u32(transaction, pointer)
    if mode > 3:
        return 0
    jump = _read_span(transaction, objects._image_address(image_base, 0x9A0B8) + mode, 1)[0]
    target = 0x25AB68 + jump * 4
    if target == 0x25AB68:
        width = (length + 15) & ~15
        if width > max_bytes:
            raise RefillUnsupported("cipher ECB exceeds the explicit byte bound")
        for offset in range(0, width, 16):
            _cipher_block(transaction, context_address, source_address + offset,
                          output_address + offset, image_base, decrypt=True)
        result = 0
    elif target == 0x25AB8C:
        result = decrypt_cipher_cbc(transaction, context_address=context_address,
            source_address=source_address, output_address=output_address, length=length,
            entry_stack_address=entry_stack_address - 0x40, image_base=image_base, max_bytes=max_bytes)
    else:
        raise RefillUnsupported("unrecovered cipher dispatch branch")
    transaction.commit()
    return result
