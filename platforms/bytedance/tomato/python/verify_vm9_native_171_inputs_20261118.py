"""Check the ordinary native callback's input conversion, before child execution.

The default checks retained synthetic evidence. --elf binds the original
Metasec sample; --libc binds the matching Bionic sample. --replay requires both
and executes the original callback with a warm synthetic root/child graph.
Memory/allocation providers are explicit; no Android or signing VM runs.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path

from verify_vm9_registered_security_handoff_20261118 import SHA256, load_elf, is_digest

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence/vm9_native_171_inputs_20261118.json'
LIBC_SHA256 = 'd2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
LIBC_BASE = 0x51000000
GUEST = 0x70000000
URL = b'https://example.invalid/path'
RANGES = [(0x27ED14, 0x27ED70), (0x27F84C, 0x27FEF4), (0x27FEF4, 0x2800FC)]
DATA_RANGES = [(0xA63FC, 0xA6404)]
EXPECTED = [
    (0x27ED2C, 'ldp', 'x8, x1, [x0]'), (0x27ED34, 'bl', '#0x27f84c'),
    (0x27FB34, 'ldr', 'x8, [x8, #0x950]'), (0x27FB38, 'ldr', 'x26, [x8, #0x18]'),
    (0x27FB5C, 'mov', 'w3, #0x171'), (0x27FB64, 'ldr', 'x9, [x8, #0x20]'),
    (0x27FB70, 'blr', 'x9'), (0x27FF34, 'ldar', 'w9, [x20]'),
    (0x27FF54, 'bl', '#0x167e54'), (0x27FF5C, 'stlr', 'w8, [x20]'),
    (0x27FFA4, 'bl', '#0x248344'), (0x27FFB4, 'bl', '#0x248344'),
    (0x27FFC4, 'bl', '#0x19e038'), (0x27FFDC, 'bl', '#0x25c324'),
    (0x27FFE4, 'bl', '#0x25c71c'), (0x27FFE8, 'cbz', 'x0, #0x2800bc'),
    (0x27FFF4, 'tbnz', 'w0, #0, #0x2800bc'),
    (0x28008C, 'bl', '#0x2483e0'), (0x2800A0, 'bl', '#0x2483e0'),
    (0x2800B0, 'bl', '#0x25bf3c'), (0x2800C0, 'bl', '#0x185404'),
]
# PLT entry, symbol, and whether this oracle executes the matching Bionic body.
IMPORTS = {
    0x347F00: ('pthread_mutex_lock', True), 0x347F10: ('pthread_mutex_unlock', True),
    0x347F20: ('memset', False), 0x347F40: ('strlen', False),
    0x347F60: ('memcpy', False), 0x347FA0: ('free', False),
    0x347FD0: ('malloc', False), 0x347FE0: ('memcmp', True),
    0x3480B0: ('strcmp', True), 0x348320: ('realloc', False),
    0x348410: ('memmove', False),
}
BOUNDARY = dict(entry='0x27ed14', input_function='0x27f84c', parser='0x27fef4',
    splitter='0x19e038', virtual_call='0x27fb70', virtual_slot='0x20',
    child_vtable='0x35d5f0', stop_before='0x27dd04', mode='0x171',
    delimiter_hex='0d0a', input_layout='two CString pointers in the input block',
    pairing='successive CRLF-separated fragments; one final empty fragment omitted',
    odd_or_empty_fragment_list='empty tree and callback returns zero',
    duplicate_key='case-sensitive byte key; last value replaces earlier value')
CLAIMS = dict(original_callback_input_conversion_synthetic_replay_verified=True,
    synthetic_child_virtual_call_to_dispatcher_entry_verified=True,
    semantic_input_expectations_match=True, rejected_inputs_temporary_allocations_released=True,
    synthetic_uncontended_Bionic_recursive_mutex_instructions_executed=True,
    actual_business_arguments_observed=False, actual_business_callback_execution_verified=False,
    cold_root_graph_initialization_verified=False, child_dispatcher_body_executed=False,
    mode_171_and_138_VM_equivalence_verified=False, prefix_callback_branch_verified=False,
    complete_native_callback_return_path_verified=False,
    whole_heap_native_Python_model_differential_verified=False,
    ordinary_cronet_six_head_chain_verified=False, complete_standalone_signer_verified=False,
    original_signature_runtime_equivalence_verified=False, online_header_acceptance_verified=False)
PROVIDERS = dict(
    synthetic=['malloc', 'realloc', 'free', 'strlen', 'memcpy', 'memmove', 'memset'],
    original_matching_Bionic=['pthread_mutex_lock', 'pthread_mutex_unlock', 'memcmp', 'strcmp'],
    internal_Metasec_helpers_substituted=False, allocation_failure_paths_exercised=False,
    mutex_contention_or_kernel_paths_exercised=False)
LIMITS = [
    'Inputs, TLS, root/child graph, initialized diagnostic buckets and comparison singleton are synthetic',
    'The root guard is warm; graph construction, diagnostic initialization and runtime object identity are not established',
    'External memory/allocation services are explicit synthetic providers; this is not Android allocator equivalence',
    'Matching Bionic executes only bounded uncontended paths; failures, contention and kernel behavior are not covered',
    'Execution reaches but never executes the child dispatcher; the VM, returned output tree and successful callback cleanup remain unverified',
    'Input names describe synthetic controls; no real request argument semantics or same-request Cronet execution is established',
    'Native mode 0x171 must not be replaced with the Java facade mode 0x138 without a separate proof',
    'Heap/ledger digests retain an original-code replay checkpoint, not a full Python ownership-model differential',
]


def controls():
    samples = [
        ('empty', b''), ('one', b'key'), ('pair', b'key\r\nvalue'),
        ('trailing', b'key\r\nvalue\r\n'), ('odd', b'key\r\nvalue\r\nextra'),
        ('two_pairs', b'b\r\n2\r\na\r\n1\r\n'),
        ('duplicate', b'key\r\nold\r\nkey\r\nnew\r\n'),
        ('empty_key', b'\r\nvalue\r\n'), ('empty_value', b'key\r\n\r\n'),
        ('two_empty', b'\r\n\r\n'), ('sole_separator', b'\r\n'),
        ('colon', b'key: value\r\n'), ('lf_only', b'key\nvalue\n'),
        ('blank_tail', b'key\r\nvalue\r\n\r\n'),
        ('nul_after_pair', b'key\r\nvalue\0\r\nextra'),
        ('nul_before_value', b'key\0\r\nvalue'),
        ('case_sensitive', b'K\r\nupper\r\nk\r\nlower'),
        ('colon_pairs', b'key: value\r\nother: value\r\n'),
        ('space', b' key \r\n value \r\n'), ('binary', b'\xff\r\n\x80'),
        ('null_first', b'key\r\nvalue'), ('null_second', b'key\r\nvalue'),
    ]
    rows = []
    for index, base in enumerate((0x10000000, 0x6000000000)):
        selected = samples if not index else [samples[i] for i in (0, 2, 6, 19, 20, 21)]
        rows.extend(dict(base=base, label=label, delimiter_initialized=bool(index),
                         first_hex=None if label == 'null_first' else URL.hex(),
                         second_hex=None if label == 'null_second' else text.hex())
                    for label, text in selected)
    for base, warm in ((0x10000000, True), (0x6000000000, False)):
        rows.append(dict(base=base, label='pair_other_delimiter_state', delimiter_initialized=warm,
                         first_hex=URL.hex(), second_hex=b'key\r\nvalue'.hex()))
    for label, first in (('empty_first', b''), ('nul_in_first', b'url\0ignored')):
        rows.append(dict(base=0x6000000000, label=label, delimiter_initialized=False,
                         first_hex=first.hex(), second_hex=b'key\r\nvalue'.hex()))
    return rows


def expected_pairs(control):
    if control['first_hex'] is None or control['second_hex'] is None:
        return []
    text = bytes.fromhex(control['second_hex']).split(b'\0', 1)[0]
    tokens = text.split(b'\r\n') if text else []
    if tokens and text.endswith(b'\r\n'):
        tokens.pop()
    pairs = sorted(dict(zip(tokens[::2], tokens[1::2])).items()) if len(tokens) % 2 == 0 else []
    return [[key.hex(), value.hex()] for key, value in pairs]


def digest_json(value):
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), sort_keys=True).encode()).hexdigest()


def validate_case(row, control):
    assert row['control'] == control
    pairs = expected_pairs(control)
    assert row['pairs_hex'] == pairs
    reached = bool(pairs)
    assert row['outcome'] == ('child_entry' if reached else 'zero_return')
    assert row['child_dispatcher_instructions_executed'] == 0
    assert row['original_executed_code_unchanged'] is True
    assert row['forbidden_boundary_calls'] == 0
    assert row['instructions_executed'] > 0
    assert row['Bionic_instructions_executed'] >= 0
    for key in ('trace_sha256', 'guest_heap_sha256', 'allocation_ledger_sha256', 'mutex_ledger_sha256'):
        assert is_digest(row[key])
    assert row['allocation_provider_calls'] >= 0
    assert all(name in {v[0] for v in IMPORTS.values()} and type(count) is int and count > 0
               for name, count in row['external_calls'].items())
    if reached:
        assert row['handoff'] == dict(child_guest_offset='0x3100', target='0x27dd04', mode='0x171',
            url_hex=bytes.fromhex(control['first_hex']).split(b'\0', 1)[0].hex(),
            url_reference_count=2, tree_reference_count=2, output_reference_frame_offset='-0x48')
        assert row['live_allocations'] == 7 + 6 * len(pairs)
        assert row['mutex_events'] == 12 and row['Bionic_instructions_executed'] > 0
    else:
        assert row['handoff'] is None and row['returned_word'] == 0
        assert row['live_allocations'] == 0
        assert row['mutex_events'] == (0 if control['label'].startswith('null_') else 12)
        if control['label'].startswith('null_'):
            assert row['allocation_provider_calls'] == 0
            assert row['external_calls'] == {} and row['Bionic_instructions_executed'] == 0


def validate(data):
    assert data['schema'] == 'vm9-native-171-inputs-20261118-v1'
    assert data['provenance']['Metasec_sha256'] == SHA256
    assert data['provenance']['Bionic_sha256'] == LIBC_SHA256
    assert data['provenance']['upstream_evidence'] == 'vm9_registered_security_handoff_20261118.json'
    assert data['claims'] == CLAIMS and data['boundary'] == BOUNDARY and data['providers'] == PROVIDERS
    assert data['limits'] == LIMITS
    assert data['synthetic_memory_only'] is True and data['Android_execution'] is False
    assert data['real_request_values_or_connection_details_published'] is False
    assert data['static_instruction_bindings'] == [dict(offset=hex(a), mnemonic=m, operands=s) for a,m,s in EXPECTED]
    for name, ranges in (('code_ranges', RANGES), ('data_ranges', DATA_RANGES)):
        assert [(int(r['start'], 16), int(r['end_exclusive'], 16)) for r in data[name]] == ranges
        assert all(is_digest(r['sha256']) for r in data[name])
    assert data['import_bindings'] == [dict(plt=hex(a), name=n, matching_Bionic_body=b)
                                       for a, (n, b) in IMPORTS.items()]
    assert len(data['case_results']) == len(controls())
    for row, control in zip(data['case_results'], controls()):
        validate_case(row, control)


def libc_image(path):
    from elftools.elf.elffile import ELFFile
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == LIBC_SHA256, 'different Bionic sample'
    elf = ELFFile(BytesIO(raw))
    exports = {s.name: LIBC_BASE + s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()
               if s['st_shndx'] != 'SHN_UNDEF' and s['st_value']}
    return elf, exports


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    elf, _, read = load_elf(path)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for off, mnemonic, operands in EXPECTED:
        ins, = decoder.disasm(read(off, 4), off)
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), hex(off)
    for row in data['code_ranges'] + data['data_ranges']:
        start, end = int(row['start'], 16), int(row['end_exclusive'], 16)
        assert hashlib.sha256(read(start, end-start)).hexdigest() == row['sha256']
    symbols = elf.get_section_by_name('.dynsym')
    imports = {r['r_offset']: symbols.get_symbol(r['r_info_sym']).name
               for r in elf.get_section_by_name('.rela.plt').iter_relocations()}
    for offset, (name, _) in IMPORTS.items():
        # The original three-instruction ADRP/LDR/ADD PLT stub encodes its GOT slot.
        ins = list(decoder.disasm(read(offset, 12), offset))
        assert len(ins) == 3 and ins[0].mnemonic == 'adrp' and ins[1].mnemonic == 'ldr'
        page = int(ins[0].op_str.split('#')[1], 16)
        displacement = int(ins[1].op_str.split('#')[1].split(']')[0], 16) if '#' in ins[1].op_str else 0
        assert imports[page + displacement] == name
    refs = {r['r_offset']: r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()
            if r['r_info_type'] == 1027 and r['r_offset'] == 0x35D610}
    assert refs == {0x35D610: 0x27DD04}
    return dict(instructions=len(EXPECTED), code_ranges=len(RANGES), data_ranges=len(DATA_RANGES),
                imports=len(IMPORTS), relative_relocations=1)


def fixture_pages(image, control):
    """Fresh synthetic warm input graph shared by bounded continuation probes."""
    import verify_vm9_signer_objects as oracle
    from vm9_allocator import _write_span
    base = control['base']; tls = GUEST + 0xD000
    pages = {page: bytearray(data) for page, data in image.items()}
    pages.update(oracle.fresh_pages())
    def write(address, value, size=8):
        _write_span(pages, address, value.to_bytes(size, 'little'))
    for field, off in (('first_hex', 0x1000), ('second_hex', 0x2000)):
        _write_span(pages, GUEST+off, bytes.fromhex(control[field] or '')+b'\0')
    write(GUEST+0x800, 0 if control['first_hex'] is None else GUEST+0x1000)
    write(GUEST+0x808, 0 if control['second_hex'] is None else GUEST+0x2000)
    write(tls+8, tls+0x200); _write_span(pages, tls+0x200, bytes(0x900))
    write(tls+0x210, 137, 4); write(tls+0x28, 0xAB567823C091D200)
    write(base+0x3E0960, 1, 1); write(base+0x3E0950, GUEST+0x3000); write(base+0x3E0958, 0)
    write(GUEST+0x3018, GUEST+0x3100); write(GUEST+0x3100, base+0x35D5F0)
    write(base+0x3DEDA0, 1, 1); write(base+0x3DEDA8, GUEST+0xA000)
    for i in range(256): write(GUEST+0xA000+8*i, GUEST+0xB000)
    _write_span(pages, GUEST+0xB000, bytes(0x30)); write(GUEST+0xB008, 0x4000, 4)
    write(base+0x3D1680, 1, 1); write(base+0x3D1678, GUEST+0xB100)
    write(GUEST+0xB100, GUEST+0xB200); _write_span(pages, GUEST+0xB200, bytes(0x88))
    if control['delimiter_initialized']:
        write(base+0x3E094C, 1, 4); _write_span(pages, base+0x3E0948, b'\r\n\0')
    return pages


def replay(path, libc, *, case_controls=None, on_case=None):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from unicorn import arm64_const as arm
    import verify_vm9_signer_objects as oracle
    from verify_vm9_strings import Effects
    _, main_loads, read_main = load_elf(path)
    libc_elf, exports = libc_image(libc)
    libc_loads = [s for s in libc_elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    libc_payloads = [(s['p_vaddr'], s.data()) for s in libc_loads]
    def read_libc(address):
        start, payload = next((a, b) for a,b in libc_payloads if a <= address and address+4 <= a+len(b))
        return payload[address-start:address-start+4]
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoded = set()
    selected = controls() if case_controls is None else case_controls
    # Build once per image base; each case gets private mutable copies.
    images = {base: oracle.image_pages(path, base) for base in {c['base'] for c in selected}}
    rows = []
    for control in selected:
        base = control['base']; tls = GUEST + 0xD000
        pages = fixture_pages(images[base], control)
        effects = Effects(blocks=())
        trace, handoffs, executed_code = [], [], {}
        external = Counter(); bionic_count = 0
        executable_spans = [(base+s['p_vaddr'], base+s['p_vaddr']+s['p_memsz'])
                            for s in main_loads if s['p_flags'] & 1]
        executable_spans += [(LIBC_BASE+s['p_vaddr'], LIBC_BASE+s['p_vaddr']+s['p_memsz'])
                             for s in libc_loads if s['p_flags'] & 1]
        def redirect(name):
            def call(cpu): cpu.reg_write(arm.UC_ARM64_REG_PC, exports[name])
            return call
        imports = {
            0x347FA0: lambda c: effects.native(c, 'free', pointer=c.reg_read(arm.UC_ARM64_REG_X0)),
            0x348320: lambda c: effects.native(c, 'realloc', c.reg_read(arm.UC_ARM64_REG_X1), c.reg_read(arm.UC_ARM64_REG_X0)),
            0x347FE0: redirect('memcmp'), 0x3480B0: redirect('strcmp'),
        }
        def observe(cpu, address):
            nonlocal bionic_count
            if LIBC_BASE <= address < LIBC_BASE + 0x200000:
                off = address-LIBC_BASE; domain = 'libc'; bionic_count += 1
                original = read_libc(off)
            else:
                off = address-base; domain = 'metasec'; original = read_main(off, 4)
                assert off not in (0x26EDC4, 0x26E70C, 0x15F094, 0x264158, 0x27DD04), hex(off)
                if off in IMPORTS: external[IMPORTS[off][0]] += 1
                elif 0x347E00 <= off < 0x348800: raise AssertionError('unexpected import '+hex(off))
            trace.append([domain, off])
            site = (domain, off)
            if site not in decoded:
                instruction, = decoder.disasm(original, off)
                assert instruction.mnemonic not in ('svc', 'hvc', 'smc', 'brk', 'hlt'), site
                decoded.add(site)
            if site not in executed_code:
                assert bytes(cpu.mem_read(address, 4)) == original, site
                executed_code[site] = (address, original)
            if address != base+0x27FB70: return
            def u64(a): return int.from_bytes(cpu.mem_read(a, 8), 'little')
            def string(a):
                assert u64(a) == base+0x34F5F8
                length = int.from_bytes(cpu.mem_read(a+12, 4), 'little')
                assert length <= 0x1000
                return bytes(cpu.mem_read(u64(a+16), length))
            child, url_ref, tree_ref, mode = [cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X'+str(i))) for i in range(4)]
            assert child == GUEST+0x3100 and mode == 0x171
            assert cpu.reg_read(arm.UC_ARM64_REG_X9) == base+0x27DD04
            container = u64(tree_ref)
            assert u64(container) == base+0x35B7C0
            controller = u64(container+32); sentinel = u64(controller)
            pairs, visited = [], set()
            def walk(node, parent):
                if not node: return
                assert node not in visited and len(visited) < 128 and u64(node+8) == parent
                visited.add(node); walk(u64(node+16), node)
                pair = u64(node+32)
                pairs.append([string(u64(pair)).hex(), string(u64(pair+8)).hex()])
                walk(u64(node+24), node)
            walk(u64(sentinel+8), sentinel)
            assert len(pairs) == u64(controller+8) and pairs == expected_pairs(control)
            output = cpu.reg_read(arm.UC_ARM64_REG_X8)
            assert output == cpu.reg_read(arm.UC_ARM64_REG_X29)-0x48
            cpu.mem_read(output, 16)  # Sret storage is addressable; no initialization is assumed.
            handoffs.append(dict(child_guest_offset=hex(child-GUEST), target='0x27dd04', mode=hex(mode),
                url_hex=string(u64(url_ref)).hex(),
                url_reference_count=int.from_bytes(cpu.mem_read(u64(url_ref+8), 4), 'little'),
                tree_reference_count=int.from_bytes(cpu.mem_read(u64(tree_ref+8), 4), 'little'),
                output_reference_frame_offset='-0x48'))
        expected = expected_pairs(control)
        observed = {(base+0x3E0948, 8): None, (GUEST+0xB008, 8): None}
        def write_observer(cpu, address, width):
            assert not any(address < end and start < address+width for start,end in executable_spans), hex(address)
        result, memory, default_alloc, locks = oracle.native(path, base, 0x27ED14,
            [GUEST+0x800, 0, 0], pages, libc=libc,
            real_singletons=True, real_mutexes=True, real_recursive_mutexes=True,
            real_diagnostics=True, real_jni_acquisition=True, real_jni_dispatch=True,
            stop_offset=0x27DD04 if expected else None,
            extra_registers={arm.UC_ARM64_REG_TPIDR_EL0: tls},
            malloc_handler=lambda c,n: effects.native(c, 'malloc', n), host_imports=imports,
            instruction_observer=observe, memory_write_observer=write_observer,
            observed_memory=observed, instruction_limit=100000)
        assert not default_alloc and len(handoffs) == bool(expected)
        if expected: assert result == GUEST+0x3100
        else: assert result == 0 and not effects.blocks
        if control['first_hex'] is not None and control['second_hex'] is not None:
            assert observed[base+0x3E0948, 8] == b'\r\n\0\0\x01\0\0\0'
        assert observed[GUEST+0xB008, 8] == b'\0\x40\0\0\0\0\0\0'
        normalized_alloc = [[event[0], *[v-GUEST if GUEST <= v < GUEST+0x10000 else v for v in event[1:]]]
                            for event in effects.calls]
        normalized_locks = [[name, addr-GUEST] for name, addr in locks]
        rows.append(dict(control=control, pairs_hex=expected, outcome='child_entry' if expected else 'zero_return',
            handoff=handoffs[0] if handoffs else None, returned_word=None if expected else result,
            instructions_executed=len(trace)-sum(external.values()), Bionic_instructions_executed=bionic_count,
            trace_sha256=digest_json(trace), guest_heap_sha256=hashlib.sha256(memory).hexdigest(),
            allocation_provider_calls=len(effects.calls), allocation_ledger_sha256=digest_json(normalized_alloc),
            live_allocations=len(effects.blocks), mutex_events=len(locks), mutex_ledger_sha256=digest_json(normalized_locks),
            external_calls=dict(sorted(external.items())), child_dispatcher_instructions_executed=0,
            original_executed_code_unchanged=True, forbidden_boundary_calls=0))
        validate_case(rows[-1], control)
        if on_case is not None: on_case(rows[-1])
    return rows


def build(path, libc, *, on_case=None):
    _, _, read = load_elf(path); libc_image(libc)
    data = dict(schema='vm9-native-171-inputs-20261118-v1',
        provenance=dict(Metasec_sha256=SHA256, Bionic_sha256=LIBC_SHA256,
                        upstream_evidence='vm9_registered_security_handoff_20261118.json'),
        boundary=BOUNDARY, claims=CLAIMS, providers=PROVIDERS, limits=LIMITS,
        synthetic_memory_only=True, Android_execution=False,
        real_request_values_or_connection_details_published=False,
        static_instruction_bindings=[dict(offset=hex(a), mnemonic=m, operands=s) for a,m,s in EXPECTED],
        import_bindings=[dict(plt=hex(a), name=n, matching_Bionic_body=b) for a,(n,b) in IMPORTS.items()],
        code_ranges=[dict(start=hex(a), end_exclusive=hex(b), sha256=hashlib.sha256(read(a,b-a)).hexdigest()) for a,b in RANGES],
        data_ranges=[dict(start=hex(a), end_exclusive=hex(b), sha256=hashlib.sha256(read(a,b-a)).hexdigest()) for a,b in DATA_RANGES],
        case_results=[])
    verify_elf(data, path)
    data['case_results'] = replay(path, libc, on_case=on_case)
    validate(data)
    return data


def negatives(data):
    mutations = [('claims', key, not value) for key,value in CLAIMS.items()]
    mutations += [('boundary', 'mode', '0x138'), ('boundary', 'delimiter_hex', '0a')]
    rejected = 0
    for section, key, value in mutations:
        bad = deepcopy(data); bad[section][key] = value
        try: validate(bad)
        except AssertionError: rejected += 1
        else: raise AssertionError('damaged boundary/claim accepted')
    for index in range(len(controls())):
        for key, value in (('outcome', 'VM_executed'),
                           ('pairs_hex', data['case_results'][index]['pairs_hex']+[['00', '00']])):
            bad = deepcopy(data); bad['case_results'][index][key] = value
            try: validate(bad)
            except AssertionError: rejected += 1
            else: raise AssertionError('damaged case accepted')
    for mutate in (
        lambda d: d['provenance'].__setitem__('Metasec_sha256', '0'*64),
        lambda d: d['provenance'].__setitem__('Bionic_sha256', '0'*64),
        lambda d: d.__setitem__('Android_execution', True),
        lambda d: d.__setitem__('real_request_values_or_connection_details_published', True),
        lambda d: d['providers'].__setitem__('internal_Metasec_helpers_substituted', True),
        lambda d: d['import_bindings'][0].__setitem__('name', 'unbound'),
        lambda d: d['case_results'][2]['handoff'].__setitem__('url_reference_count', 1),
        lambda d: d['case_results'][0].__setitem__('live_allocations', 1),
    ):
        bad = deepcopy(data); mutate(bad)
        try: validate(bad)
        except AssertionError: rejected += 1
        else: raise AssertionError('damaged provenance/provider/ownership accepted')
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, help='Pinned original libmetasec_ml.so')
    parser.add_argument('--libc', type=Path, help='Pinned matching Bionic libc.so')
    parser.add_argument('--replay', action='store_true', help='Execute original callback in isolated Unicorn memory')
    args = parser.parse_args()
    if args.replay and (not args.elf or not args.libc): parser.error('--replay requires --elf and --libc')
    data = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    validate(data)
    result = dict(retained_synthetic_cases=len(controls()), damaged_evidence_rejected=negatives(data),
                  child_dispatcher_body_executed=False, actual_business_callback_execution_verified=False)
    if args.elf: result['Metasec_bindings'] = verify_elf(data, args.elf)
    if args.libc: libc_image(args.libc); result['matching_Bionic_digest_verified'] = True
    if args.replay:
        assert replay(args.elf, args.libc) == data['case_results'], 'frozen replay differs'
        result['original_code_cases_replayed'] = len(controls())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
