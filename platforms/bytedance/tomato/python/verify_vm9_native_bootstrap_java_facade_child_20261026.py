"""Continue one fresh native bootstrap CPU through the Java facade and child.

The receiver/tree and child vtable target are explicit bounded probe inputs.
Bootstrap state, facade helpers, owning VM and callback imports execute on the
same CPU; the verifier records the bounded continuation without synthesizing a
dispatch table or treating a non-STOP return as signer output.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, r'C:\AI\6\_repo_stage\platforms\bytedance\tomato\python')
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as arm
import verify_vm9_bootstrap_request_memcpy_continuation_20261026 as cont
import verify_vm9_jni_complete_bootstrap_20261011 as bootstrap
import verify_vm9_elf_constructor_sequence_20261011 as sequence
import verify_vm9_java_request_facade_fresh_20261020 as facade
import verify_vm9_jni_header_input_fresh_20261020 as headers
import verify_vm9_signer_objects as oracle

BASES = (0x122C0000, 0x775C205000)
TABLE_PAGE_OFFSET = 0x13BB000
G = headers.G

def w(cpu, a, v, n=8): cpu.mem_write(a, int(v).to_bytes(n, 'little', signed=False))

def run(library, libc, image):
    profile = {} if image == BASES[0] else {
        'allocation_delta': 0xC00, 'thread_id': 1, 'padding': 0xFF, 'stack_padding': 0x39}
    stack = sequence.v.SP if image == BASES[0] else sequence.v.SP - 0xC80
    args = argparse.Namespace(library=library, libc=libc)
    pages = bootstrap.fresh(args, image, profile, Python=True)
    cpu, boot_service, _vm, _jni, _scopes = bootstrap.native(
        args, pages, image, profile, stack, 0)
    # Keep bootstrap-owned malloc/free effects while moving the next native
    # facade allocations into the already mapped low scratch arena.
    boot_service.cursor = 0x780F0000
    facade_pages, facade_args = facade.fixture(library, image, 'normal')
    cont._overlay_request_fixture(cpu, facade_pages)
    cont._restore_bootstrapped_jni_pages(cpu)

    # Keep the external runtime area canary-only; no dispatch table is supplied.
    table_start = image + TABLE_PAGE_OFFSET
    for index in range(2):
        address = table_start + index * 0x1000
        cpu.mem_map(address, 0x1000)
        cpu.mem_write(address, bytes([0xA5]) * 0x1000)

    receiver = G + 0x3000
    mutex = G + 0x3200
    container = G + 0x3400
    control = G + 0x3600
    sentinel = G + 0x3800
    node = G + 0x3A00
    pair = G + 0x3C00
    fallback = G + 0x3E00
    context = G + 0x4000
    cpu.mem_write(mutex, bytes(0x98))
    for address, value in (
        (G + 0x1300 + 0x18, receiver),
        (receiver, image + 0x35D5F0),
        (receiver + 8, mutex), (receiver + 0x10, container),
        (receiver + 0x20, fallback),
        (container, image + 0x35B828), (container + 0x20, control),
        (control, sentinel), (control + 8, 1),
        (sentinel, 1), (sentinel + 8, node),
        (sentinel + 0x10, node), (sentinel + 0x18, node),
        (node, 1), (node + 8, sentinel), (node + 0x18, 0),
        (node + 0x20, pair), (pair, image + 0x2830C4), (pair + 8, context),
        (fallback, 0), (fallback + 8, context),
        (image + 0x35D5F0 + 0x20, image + 0x27DD04),
    ):
        w(cpu, address, value)

    # Use fresh facade JNI semantics on private target addresses.  The live
    # bootstrap environment is translated only at the provider boundary.
    service = facade.Services(image, 'normal')
    original_jni = service.jni
    def bridge(fn, args, read, write):
        return original_jni(fn, (headers.ENV,) + tuple(args[1:]), read, write)
    service.jni = bridge
    jni_imports = service.imports(image)
    jni_handlers = {}
    table = G + 0x6000
    for index, slot in enumerate(headers.SLOTS):
        old = G + 0xF400 + index * 16
        new = G + 0xF800 + index * 16
        jni_handlers[new] = jni_imports[old - image]
        w(cpu, table + slot, new)

    def jni_hook(c, address, _size, _user):
        result = jni_handlers[address](c)
        c.reg_write(arm.UC_ARM64_REG_X0, 0 if result is None else result)
        c.reg_write(arm.UC_ARM64_REG_PC, c.reg_read(arm.UC_ARM64_REG_X30))
    cpu.hook_add(UC_HOOK_CODE, jni_hook, begin=G + 0xF800, end=G + 0xF900)

    def calloc_hook(c, address, _size, _user):
        count = c.reg_read(arm.UC_ARM64_REG_X0)
        size = c.reg_read(arm.UC_ARM64_REG_X1)
        if count != 1:
            raise RuntimeError(f'facade calloc count {count}')
        pointer = boot_service.allocate(None, size)
        c.mem_write(pointer, bytes(size))
        c.reg_write(arm.UC_ARM64_REG_X0, pointer)
        c.reg_write(arm.UC_ARM64_REG_PC, c.reg_read(arm.UC_ARM64_REG_X30))
    cpu.hook_add(UC_HOOK_CODE, calloc_hook, begin=image + 0x3482B0, end=image + 0x3482B0)

    markers = []
    imports = []
    reads = writes = 0
    unmapped = []
    instructions = 0
    def code(c, address, _size, _user):
        nonlocal instructions
        instructions += 1
        offset = address - image
        if offset in (0x17B8F8, 0x26FC94, 0x26FE2C, 0x25C324,
                      0x27DD04, 0x2830C4, 0x168324,
                      0x170308, 0x2858A8, 0x2858B4, 0x347F60):
            markers.append({'pc': hex(offset), 'x0': hex(c.reg_read(arm.UC_ARM64_REG_X0)),
                            'x1': hex(c.reg_read(arm.UC_ARM64_REG_X1)),
                            'x2': hex(c.reg_read(arm.UC_ARM64_REG_X2)),
                            'x3': hex(c.reg_read(arm.UC_ARM64_REG_X3)),
                            'x8': hex(c.reg_read(arm.UC_ARM64_REG_X8))})
        if address >= G + 0xF800 and address < G + 0xF900:
            imports.append(hex(address - G))
    def read_hook(c, _access, address, size, _value, _user):
        nonlocal reads
        if table_start <= address < table_start + 0x2000: reads += 1
    def write_hook(c, _access, address, size, _value, _user):
        nonlocal writes
        if table_start <= address < table_start + 0x2000: writes += 1
    def bad(c, access, address, size, value, _user):
        unmapped.append({'pc_offset': hex(c.reg_read(arm.UC_ARM64_REG_PC) - image),
                         'access': access, 'address': hex(address), 'size': size,
                         'value': hex(value)})
    cpu.hook_add(UC_HOOK_CODE, code, begin=image + 0x15DB00, end=image + 0x348800)
    cpu.hook_add(UC_HOOK_MEM_READ, read_hook)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    cpu.hook_add(UC_HOOK_MEM_UNMAPPED, bad)
    cpu.reg_write(arm.UC_ARM64_REG_X0, bootstrap.cold.ENV)
    cpu.reg_write(arm.UC_ARM64_REG_X1, G + 0x1300)
    cpu.reg_write(arm.UC_ARM64_REG_X2, facade_args['url_reference'])
    cpu.reg_write(arm.UC_ARM64_REG_X3, facade_args['header_array_reference'])
    cpu.reg_write(arm.UC_ARM64_REG_SP, headers.SP)
    cpu.reg_write(arm.UC_ARM64_REG_X30, oracle.STOP)
    outcome, error = 'returned', None
    try:
        cpu.emu_start(image + 0x17B8F8, oracle.STOP, count=180_000)
    except Exception as exc:
        outcome, error = 'stopped', f'{type(exc).__name__}: {exc}'
    pc = cpu.reg_read(arm.UC_ARM64_REG_PC)
    if error is None and pc != oracle.STOP:
        outcome = 'bounded_instruction_limit'
    return {
        'image_base': hex(image), 'outcome': outcome, 'error': error,
        'stop_pc': hex(pc), 'stop_pc_offset': hex(pc - image),
        'request_reached_oracle_stop': pc == oracle.STOP,
        'bounded_instruction_limit': pc != oracle.STOP and error is None,
        'native_instructions_observed': instructions,
        'markers': markers, 'jni_import_count': len(imports),
        'runtime_table_read_count': reads, 'runtime_table_write_count': writes,
        'unmapped_events': unmapped,
        'synthetic_dispatch_table_used': False,
        'synthetic_callback_vtable_used': False,
        'normal_facade_entry_used': True,
        'normal_facade_child_target_injected': True,
        'native_bootstrap_same_cpu': True,
        'native_facade_conversion_helpers_observed': [
            marker['pc'] for marker in markers
            if marker['pc'] in ('0x26fe2c', '0x26fc94', '0x25c324')
        ],
        'native_child_to_owning_vm_observed': [
            marker['pc'] for marker in markers
            if marker['pc'] in ('0x27dd04', '0x2830c4', '0x168324')
        ],
        'real_memcpy_import_continuation_observed': any(
            marker['pc'] == '0x347f60' for marker in markers
        ),
        'whole_request_native_differential_verified': False,
        'fresh_standalone_signer_verified': False,
        'online_header_acceptance_verified': False,
    }

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--library', type=Path, required=True)
    ap.add_argument('--libc', type=Path, required=True); ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); assert hashlib.sha256(a.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    rows = [run(a.library, a.libc, image) for image in BASES]
    out = {'schema': 'vm9-native-bootstrap-java-facade-child-probe-20261026-v1',
           'evidence_date': '2026-10-26',
           'sample_sha256': oracle.LIBRARY_SHA256,
           'matching_libc_sha256': hashlib.sha256(a.libc.read_bytes()).hexdigest(),
           'cases': rows, 'normal_facade_entry_used': True,
           'normal_facade_child_target_injected': True,
           'synthetic_receiver_tree_used': True,
           'native_bootstrap_same_cpu': True,
           'synthetic_dispatch_table_used': False,
           'whole_request_native_differential_verified': False,
           'fresh_standalone_signer_verified': False,
           'online_header_acceptance_verified': False,
           'interpretation': 'Same-CPU native bootstrap is followed by facade +0x17b8f8 with a deliberately injected child vtable target +0x27dd04. JNI conversion and bootstrap state are native on the same CPU; the child target field and receiver tree are still explicit probe inputs. Any unresolved stop is recorded without synthesizing a dispatch table or signer output.'}
    a.output.write_text(json.dumps(out, indent=2) + '\n', encoding='utf-8')
    print('facade bootstrap probe', len(rows), 'cases')
if __name__ == '__main__': main()
