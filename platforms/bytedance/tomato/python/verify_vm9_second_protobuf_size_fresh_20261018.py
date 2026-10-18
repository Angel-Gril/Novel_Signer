"""Fresh synthetic descriptors through the original Protobuf-C size trampoline."""
from pathlib import Path
import argparse, hashlib, json, struct
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
import vm9_protobuf as protobuf
from vm9_allocator import RefillUnsupported, _read_span, _write_span

G = oracle.GUEST
SP = G + 0xEF00
BASES = (0x122C0000, 0x775C205000)
BLOCK, MESSAGE, DESC, TABLE, CHILD, CHILD_DESC = (G + n for n in (0x1000, 0x2000, 0x4000, 0x5000, 0x3000, 0x4100))
PROFILES = ('zero', 'signed_negative', 'signed_minimum', 'zigzag_edges', 'varint_127',
    'varint_128', 'varint_16383', 'varint_16384', 'varint_2097151', 'varint_2097152',
    'varint_268435455', 'varint_268435456', 'uint64_max', 'fixed_and_bool',
    'float_negative_zero', 'float_nan', 'float_nonzero', 'string', 'empty_string',
    'bytes_unmapped_payload', 'empty_bytes', 'nested_empty', 'nested_populated',
    'shared_child', 'tag_boundaries', 'cross_page_result')


def w(p, a, n, size=8):
    _write_span(p, a, (n & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'))


def schema(p, descriptor, table, fields):
    _write_span(p, descriptor, bytes(96))
    w(p, descriptor, protobuf.MAGIC, 4)
    w(p, descriptor + 40, 0x200)
    w(p, descriptor + 48, len(fields), 4)
    w(p, descriptor + 56, table)
    for i, (tag, kind, offset, nested) in enumerate(fields):
        at = table + i * 72
        _write_span(p, at, bytes(72))
        for off, value in ((8, tag), (12, 3), (16, kind), (24, offset)):
            w(p, at + off, value, 4)
        w(p, at + 32, nested)


def fixture(library, image, label):
    p = oracle.image_pages(library, image)
    p.update(oracle.fresh_pages())
    kinds = tuple(range(17))
    fields = [(i + 1, k, 24 + i * 16, CHILD_DESC if k == 16 else 0) for i, k in enumerate(kinds)]
    schema(p, DESC, TABLE, fields)
    schema(p, CHILD_DESC, G + 0x6000, [(1, 1, 24, 0)])
    _write_span(p, MESSAGE, bytes(0x200)); w(p, MESSAGE, DESC)
    _write_span(p, CHILD, bytes(0x200)); w(p, CHILD, CHILD_DESC)
    def value(kind, n):
        w(p, MESSAGE + 24 + kind * 16, n, protobuf.Field(0, 0, 3, kind, 0, 0, 0, 0).size if kind != 15 else 8)
    if label in ('signed_negative', 'signed_minimum'):
        for k in (0, 1, 3, 4, 13):value(k, -1 if label == 'signed_negative' else -(1 << (31 if k in (0, 1, 13) else 63)))
    elif label == 'zigzag_edges':value(1, 64); value(4, -65)
    elif label.startswith('varint_'):
        n = int(label.split('_')[1])
        for k in (0, 3, 6, 8, 13):value(k, n)
    elif label == 'uint64_max':value(3, -1); value(8, -1)
    elif label == 'fixed_and_bool':
        for k in (2, 5, 7, 9, 12):value(k, 0x81)
    elif label in ('float_negative_zero', 'float_nan', 'float_nonzero'):
        pair = {'float_negative_zero':(0x80000000, 0x8000000000000000),
                'float_nan':(0x7FC01234, 0x7FF8000000001234),
                'float_nonzero':(0x3F800000, 0xBFF0000000000000)}[label]
        value(10, pair[0]); value(11, pair[1])
    elif label in ('string', 'empty_string'):
        value(14, G + 0x7FF8); _write_span(p, G + 0x7FF8, (b'a' * 129 if label == 'string' else b'') + b'\0')
    elif label in ('bytes_unmapped_payload', 'empty_bytes'):
        value(15, 128 if label == 'bytes_unmapped_payload' else 0)
        w(p, MESSAGE + 24 + 15 * 16 + 8, 0x66000000)
    elif label in ('nested_empty', 'nested_populated', 'shared_child'):
        value(16, CHILD)
        if label != 'nested_empty':w(p, CHILD + 24, -129, 4)
        if label == 'shared_child':
            fields.append((18, 16, 24 + 17 * 16, CHILD_DESC));schema(p, DESC, TABLE, fields)
            w(p, MESSAGE + 24 + 17 * 16, CHILD)
    elif label == 'tag_boundaries':
        tags = (15, 16, 2047, 2048, 262143, 262144, 33554431, 33554432, 536870911)
        schema(p, DESC, TABLE, [(tag, 6, 24 + 4 * i, 0) for i, tag in enumerate(tags)])
        for i in range(len(tags)):w(p, MESSAGE + 24 + 4 * i, 1, 4)
    block = G + 0x8FEC if label == 'cross_page_result' else BLOCK
    _write_span(p, block, (image + 0x2A3378).to_bytes(8, 'little') + MESSAGE.to_bytes(8, 'little') + b'\xA6' * 24)
    return p, dict(argument_block_address=block, entry_stack_address=SP, image_base=image)


def original(library, image, p, kw):
    steps = [0]; minimum = [SP]; seen = set()
    def observe(cpu, address):
        steps[0] += 1; minimum[0] = min(minimum[0], cpu.reg_read(arm.UC_ARM64_REG_SP)); seen.add(address - image)
    watch = {(page << 12, 4096):None for page in p if image <= page << 12 < image + 0x400000}
    result, memory, allocations, ledger = oracle.native(library, image, 0x2889C4,
        [kw['argument_block_address']], p, observed_memory=watch, instruction_observer=observe,
        instruction_limit=50000, extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert {0x2889C4, 0x2A3378, 0x253888} <= seen and not allocations and not ledger
    assert minimum[0] >= SP - 0x1000
    return result, memory, watch, steps[0], SP - minimum[0]


def compare(library, image, label):
    p, kw = fixture(library, image, label)
    result, memory, watch, steps, stack = original(library, image, p, kw)
    callback = getattr(model, 'apply_request_287474_protobuf_size_callback', None)
    assert callable(callback), 'original Protobuf-C size wrapper returned, but the second size callback is missing'
    assert callback(p, **kw) == result
    assert _read_span(p, G, 0xA000) == memory, label
    assert all(_read_span(p, a, n) == raw for (a, n), raw in watch.items()), label
    print('PASS protobuf size', hex(image), label, steps, flush=True)
    return dict(image_base=hex(image), case=label, native_instructions=steps, native_stack_bytes=stack,
        original_wrapper_and_size_helpers_returned=True, return_and_exact_eight_byte_store_equal=True,
        all_declared_guest_and_image_bytes_equal=True, native_input_snapshot_used=False,
        physical_spills_and_register_ABI_compared=False)


GUARDS = ('wrong_target', 'NULL_packed', 'wrapped_packed', 'missing_packed', 'unaligned_stack',
    'NULL_message', 'wrapped_message', 'missing_message', 'bad_magic', 'bad_size', 'field_outside_message',
    'tag_zero', 'duplicate_tag', 'label_required', 'label_optional', 'label_repeated', 'oneof', 'packed_flag',
    'kind_unknown', 'unknown_fields', 'field_limit', 'node_limit', 'depth_limit', 'output_limit',
    'string_unterminated', 'string_limit', 'descriptor_missing', 'table_missing', 'cycle', 'nested_descriptor_mismatch',
    'packed_spill_alias', 'message_spill_alias', 'descriptor_spill_alias', 'string_spill_alias', 'partial_store')


def guards(library):
    rows = []
    for label in GUARDS:
        p, kw = fixture(library, BASES[0], 'nested_populated' if label in ('cycle', 'nested_descriptor_mismatch', 'node_limit', 'depth_limit') else 'string')
        if label == 'wrong_target':w(p, BLOCK, BASES[0] + 0x253D08)
        elif label == 'NULL_packed':kw['argument_block_address'] = 0
        elif label == 'wrapped_packed':kw['argument_block_address'] = (1 << 64) - 20
        elif label == 'missing_packed':kw['argument_block_address'] = 0x66000000
        elif label == 'unaligned_stack':kw['entry_stack_address'] += 1
        elif label in ('NULL_message', 'wrapped_message', 'missing_message'):
            w(p, BLOCK + 8, {'NULL_message':0, 'wrapped_message':(1 << 64) - 8, 'missing_message':0x66000000}[label])
        elif label == 'bad_magic':w(p, DESC, 0, 4)
        elif label == 'bad_size':w(p, DESC + 40, 16)
        elif label == 'field_outside_message':w(p, TABLE + 24, 0x200, 4)
        elif label == 'tag_zero':w(p, TABLE + 8, 0, 4)
        elif label == 'duplicate_tag':w(p, TABLE + 72 + 8, 1, 4)
        elif label.startswith('label_'):w(p, TABLE + 12, {'label_required':0, 'label_optional':1, 'label_repeated':2}[label], 4)
        elif label in ('oneof', 'packed_flag'):w(p, TABLE + 48, 4 if label == 'oneof' else 1, 4)
        elif label == 'kind_unknown':w(p, TABLE + 16, 17, 4)
        elif label == 'unknown_fields':w(p, MESSAGE + 8, 1, 4)
        elif label == 'field_limit':kw['max_fields'] = 1
        elif label == 'node_limit':kw['max_nodes'] = 1
        elif label == 'depth_limit':kw['max_depth'] = 0
        elif label == 'output_limit':kw['max_bytes'] = 64
        elif label in ('string_unterminated', 'string_limit'):
            w(p, MESSAGE + 24 + 14 * 16, G + 0x9FFF)
            _write_span(p, G + 0x9FFF, b'a');p.pop((G + 0xA000) >> 12)
            if label == 'string_limit':kw['max_bytes'] = 1
        elif label == 'descriptor_missing':w(p, MESSAGE, 0x66000000)
        elif label == 'table_missing':w(p, DESC + 56, 0x66000000)
        elif label == 'cycle':w(p, MESSAGE + 24 + 16 * 16, MESSAGE);w(p, TABLE + 16 * 72 + 32, DESC)
        elif label == 'nested_descriptor_mismatch':w(p, CHILD, DESC)
        elif label == 'packed_spill_alias':
            kw['argument_block_address'] = SP - 0x40;_write_span(p, SP - 0x40, _read_span(p, BLOCK, 40))
        elif label == 'message_spill_alias':w(p, BLOCK + 8, SP - 0x40)
        elif label == 'descriptor_spill_alias':w(p, MESSAGE, SP - 0x40)
        elif label == 'string_spill_alias':w(p, MESSAGE + 24 + 14 * 16, SP - 0x40)
        elif label == 'partial_store':
            kw['argument_block_address'] = G + 0x9FEC
            _write_span(p, G + 0x9FEC, _read_span(p, BLOCK, 20));p.pop((G + 0xA000) >> 12)
        before = {k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_protobuf_size_callback(p, **kw)
        except (RefillUnsupported, ValueError, TypeError):pass
        else:raise AssertionError(label)
        assert before == {k:bytes(v) for k,v in p.items()}, label
        rows.append(dict(case=label, rejected=True, all_model_pages_unchanged=True))
        print('PASS protobuf size refusal', label, flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library', type=Path, required=True);ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--mode', choices=('red', 'native', 'guards'), default='native');a = ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    e = dict(cases=[], negative_cases=[])
    if a.mode == 'guards':e['negative_cases'] = guards(a.library)
    else:
        for image in BASES[:1] if a.mode == 'red' else BASES:
            for label in ('signed_negative',) if a.mode == 'red' else PROFILES:
                e['cases'].append(compare(a.library, image, label))
                a.output.write_text(json.dumps(e, indent=2) + '\n', encoding='utf-8', newline='\n')
    a.output.write_text(json.dumps(dict(e, native_Python_controls=len(e['cases']), rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False, complete_python_medusa=False), indent=2) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':main()
