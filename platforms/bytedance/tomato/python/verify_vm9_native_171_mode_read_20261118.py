"""Replay the ordinary native path through its first packed-mode bytecode load.

Synthetic objects only. Stops after R1 receives s32[packed_arguments+0x18],
before +0x170310 fetches the next bytecode. The tag-only context is guarded
against reads. No internal helper, instruction or VM handler is substituted.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path

import verify_vm9_native_171_vm_prelude_20261118 as prelude

handoff = prelude.handoff
EVIDENCE = handoff.EVIDENCE.with_name('vm9_native_171_mode_read_20261118.json')
MODE_PC, LOAD, STORE, STOP = 0xF7E08, 0x170308, 0x17030C, 0x170310
MODE_WORD = 0x03024001
EXPECTED = [
    (0x1702F4, 'ldr', 'x10, [x28, x13, lsl #3]'),
    (0x1702F8, 'sxth', 'x11, w9'),
    (LOAD, 'ldrsw', 'x9, [x10, x11]'),
    (STORE, 'str', 'x9, [x28, x14, lsl #3]'),
    (STOP, 'ldr', 'w9, [x8, #4]!'),
]
BOUNDARY = dict(entry='0x27ed14', callback='0x2830c4', VM_entry='0x168324',
    bytecode_entry='0xf7720', first_mode_bytecode=hex(MODE_PC),
    bytecode_word=hex(MODE_WORD), opcode=1, base_register=4,
    destination_register=1, signed_immediate=24, read_width=4,
    native_load=hex(LOAD), native_store=hex(STORE), stop_before=hex(STOP))
CLAIMS = dict(synthetic_ordinary_path_first_mode_read_verified=True,
    packed_mode_low_u32_loaded_into_R1=True,
    nonzero_mode_padding_excluded_from_load=True,
    first_mode_read_native_and_bytecode_binding_verified=True,
    original_code_and_internal_helpers_preserved=True,
    request_bytecode_prefix_executed=True,
    packed_context_read_observed=False, context_object_read_observed=False,
    complete_context_state_verified=False, callback_return_or_success_cleanup_verified=False,
    whole_request_native_Python_differential_verified=False,
    native_171_and_Java_138_VM_equivalence_verified=False,
    actual_business_callback_execution_verified=False,
    ordinary_cronet_six_heads_verified=False, complete_standalone_signer_verified=False,
    original_signature_runtime_equivalence_verified=False, online_acceptance_verified=False)
LIMITS = [
    'All inputs, root/child/registry/context objects, TLS and inherited providers are synthetic',
    'The four controls inherit the prelude profiles and observed local callback-state model input',
    'Only the first mode operand load is closed; no fresh whole-request Python differential is claimed',
    'Context objects contain a known vtable tag only; reads of their 0x80-byte spans are rejected',
    'Execution stops after the mode register store, before the next bytecode fetch at +0x170310',
    'No clock, gettid, thread creation, JNI, Android action or new native hook is introduced',
    'Callback return, output serialization, successful cleanup and online signer acceptance are unverified',
]


def controls():
    return prelude.controls()


def upstream():
    data = json.loads(prelude.EVIDENCE.read_text(encoding='utf-8'))
    prelude.validate(data)
    return data


def replay(path, libc, *, on_case=None):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from unicorn import arm64_const as arm
    import verify_vm9_signer_objects as oracle
    from vm9_request_caller import prepare_request_caller
    _, _, read_main = handoff.inputs.load_elf(path)
    libc_elf, _ = handoff.inputs.libc_image(libc)
    libc_bytes = [(s['p_vaddr'], s.data()) for s in libc_elf.iter_segments()
                  if s['p_type'] == 'PT_LOAD']
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    proofs = []

    def runner(library, base, entry, arguments, pages, **kwargs):
        before_VM = kwargs['instruction_observer']
        state = dict(started=False, bytecode_started=False, store_reached=False, frame=None)
        observed = kwargs['observed_memory']
        trace, code, cursors, reads, loads = [], {}, [], [], []

        def reg(cpu, name):
            return cpu.reg_read(getattr(arm, 'UC_ARM64_REG_' + name.upper()))

        def word(cpu, address, size=8):
            return int.from_bytes(cpu.mem_read(address, size), 'little')

        def read(cpu, address, size):
            if not state['started']:
                return
            frame = state['frame']
            # Guard both tag-only fixtures, independently of selected context.
            for context in (handoff.CONTEXT, handoff.OTHER_CONTEXT):
                assert not (address < context+0x80 and context < address+size), 'tag-only context read'
            packed = frame.packed_arguments_address
            assert not (address < packed+0x28 and packed+0x20 < address+size), 'packed context read'
            if address < packed+0x1C and packed+0x18 < address+size:
                assert address == packed+0x18 and size == 4
                assert reg(cpu, 'pc') == base+LOAD
                assert word(cpu, frame.register_backing_address-8) == base+MODE_PC
                assert bytes(cpu.mem_read(base+MODE_PC, 4)) == MODE_WORD.to_bytes(4, 'little')
                reads.append(dict(bytecode=hex(MODE_PC), native_pc=hex(LOAD),
                    size=size, packed_offset=address-packed,
                    bytes_hex=bytes(cpu.mem_read(address, size)).hex()))

        def observe(cpu, address):
            offset = address-base
            if offset == 0x168324:
                state['started'] = True
            if not state['started']:
                before_VM(cpu, address)
                if offset == 0x2830C4:
                    snapshot = {p: bytearray(data) for p, data in pages.items()}
                    for page in range(handoff.G >> 12, (handoff.G+0x10000) >> 12):
                        snapshot[page] = bytearray(cpu.mem_read(page << 12, 4096))
                    state['frame'] = prepare_request_caller(snapshot,
                        entry_stack_address=reg(cpu, 'sp'), return_address=reg(cpu, 'x30'),
                        thread_pointer=handoff.TLS, image_base=base,
                        argument_x0=reg(cpu, 'x0'), argument_x1=reg(cpu, 'x1'),
                        argument_x2=reg(cpu, 'x2'), argument_x3=reg(cpu, 'x3'),
                        output_x8=reg(cpu, 'x8'), saved_frame_pointer=reg(cpu, 'x29'),
                        saved_x28=reg(cpu, 'x28'), saved_x19=reg(cpu, 'x19'))
                    frame = state['frame']
                    observed[frame.register_backing_address-8, 0x108] = None
                return
            frame = state['frame']
            if offset == STORE:
                assert len(reads) == len(loads) == 1
                assert reg(cpu, 'x9') == 0x171
                assert word(cpu, frame.register_backing_address+4*8) == frame.packed_arguments_address
                assert word(cpu, frame.register_backing_address-8) == base+MODE_PC
                state['store_reached'] = True
            domain, local = 'metasec', offset
            if handoff.inputs.LIBC_BASE <= address < handoff.inputs.LIBC_BASE+0x200000:
                domain, local = 'libc', address-handoff.inputs.LIBC_BASE
                start, data = next((s, b) for s, b in libc_bytes if s <= local and local+4 <= s+len(b))
                raw = data[local-start:local-start+4]
            else:
                raw = read_main(offset, 4)
                assert offset not in (0x26EDC4, 0x26E70C, 0x15F094, 0x264158)
                assert not (0x347E00 <= offset < 0x348800) or offset in handoff.inputs.IMPORTS
            assert bytes(cpu.mem_read(address, 4)) == raw
            site = (domain, local)
            if site not in code:
                ins, = decoder.disasm(raw, local)
                assert ins.mnemonic not in ('svc', 'hvc', 'smc', 'brk', 'hlt')
                code[site] = raw.hex()
            trace.append([domain, local])
            if offset == 0x1684F0:
                state['bytecode_started'] = True
            cursor = word(cpu, frame.register_backing_address-8)-base
            if state['bytecode_started'] and (not cursors or cursors[-1] != cursor):
                cursors.append(cursor)
            if offset == LOAD:
                loads.append(dict(bytecode=hex(cursor), base_register=reg(cpu, 'x13'),
                    destination_register=reg(cpu, 'x14'), signed_immediate=reg(cpu, 'x11'),
                    base_is_packed_arguments=reg(cpu, 'x10') == frame.packed_arguments_address))
            # Host-provider mem_read calls do not trigger Unicorn's guest hook.
            if offset in (0x347F60, 0x348410):
                read(cpu, reg(cpu, 'x1'), reg(cpu, 'x2'))

        kwargs.update(instruction_observer=observe, memory_read_observer=read,
            stop_offset=STOP, instruction_limit=100000)
        result = oracle.native(library, base, entry, arguments, pages, **kwargs)
        assert state['store_reached'] and len(reads) == len(loads) == 1
        backing = observed[state['frame'].register_backing_address-8, 0x108]
        assert int.from_bytes(backing[:8], 'little') == base+MODE_PC
        assert int.from_bytes(backing[16:24], 'little') == 0x171
        assert cursors[0] == 0xF7720 and cursors[-1] == MODE_PC
        assert trace[-1] == ['metasec', STORE]
        proofs.append(dict(reads=reads, decoded_load=loads[0], stored_R1='0x171',
            packed_context_reads=0, context_object_reads=0,
            post_VM_instructions_executed=len(trace),
            post_VM_trace_sha256=prelude.digest(trace),
            post_VM_code_sha256=prelude.digest([[*s, raw] for s, raw in sorted(code.items())]),
            bytecode_cursor_transitions=len(cursors),
            bytecode_cursor_sha256=prelude.digest(cursors),
            stopped_before_next_bytecode_fetch=True))
        return result

    prefix_rows = handoff.replay(path, libc, case_controls=controls(), _native_runner=runner)
    assert len(prefix_rows) == len(proofs) == len(controls())
    rows = []
    for prefix, proof, control in zip(prefix_rows, proofs, controls()):
        # The inherited zero-VM claim is intentionally not retained downstream.
        row = dict(control=control, **proof,
            prefix_instructions_executed=prefix['instructions_executed'],
            prefix_trace_sha256=prefix['trace_sha256'],
            guest_heap_sha256_at_mode_stop=prefix['guest_heap_sha256'],
            allocation_ledger_sha256=prefix['allocation_ledger_sha256'],
            mutex_ledger_sha256=prefix['mutex_ledger_sha256'], mutex_events=prefix['mutex_events'],
            shared_readers_at_stop=prefix['shared_readers_at_VM_entry'],
            mode_padding_hex=prefix['mode_padding_hex'],
            callback_context_guest_offset=prefix['callback_context_guest_offset'])
        rows.append(row)
        if on_case is not None:
            on_case(row)
    return rows


def validate(data):
    assert data['schema'] == 'vm9-native-171-mode-read-20261118-v1'
    assert data['provenance'] == dict(Metasec_sha256=handoff.inputs.SHA256,
        Bionic_sha256=handoff.inputs.LIBC_SHA256, upstream_prelude_evidence=prelude.EVIDENCE.name)
    assert data['boundary'] == BOUNDARY and data['claims'] == CLAIMS and data['limits'] == LIMITS
    assert data['providers'] == handoff.inputs.PROVIDERS
    assert data['Android_execution'] is False and data['synthetic_memory_only'] is True
    assert data['static_instruction_bindings'] == [dict(offset=hex(a), mnemonic=m, operands=s) for a,m,s in EXPECTED]
    assert data['bytecode_binding'] == dict(offset=hex(MODE_PC), bytes_hex='01400203')
    assert MODE_WORD & 63 == 1
    assert len(data['case_results']) == len(controls())
    previous = {prelude.digest(r['control']): r for r in upstream()['case_results']}
    for row, control in zip(data['case_results'], controls()):
        assert row['control'] == control
        prior = previous[prelude.digest(control)]
        assert row['reads'] == [dict(bytecode=hex(MODE_PC), native_pc=hex(LOAD),
            size=4, packed_offset=24, bytes_hex='71010000')]
        assert row['decoded_load'] == dict(bytecode=hex(MODE_PC), base_register=4,
            destination_register=1, signed_immediate=24, base_is_packed_arguments=True)
        assert row['stored_R1'] == '0x171'
        assert row['packed_context_reads'] == row['context_object_reads'] == 0
        assert row['stopped_before_next_bytecode_fetch'] is True
        assert row['post_VM_instructions_executed'] == 34029
        assert row['bytecode_cursor_transitions'] == 443
        for key in ('prefix_instructions_executed', 'prefix_trace_sha256',
            'allocation_ledger_sha256', 'mutex_ledger_sha256', 'mutex_events',
            'shared_readers_at_stop', 'mode_padding_hex', 'callback_context_guest_offset'):
            assert row[key] == prior[key], key
        for key in ('post_VM_trace_sha256', 'post_VM_code_sha256',
                    'bytecode_cursor_sha256', 'guest_heap_sha256_at_mode_stop'):
            assert handoff.inputs.is_digest(row[key]), key


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    result = prelude.verify_elf(upstream(), path)
    _, _, read = handoff.inputs.load_elf(path)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for offset, mnemonic, operands in EXPECTED:
        ins, = decoder.disasm(read(offset, 4), offset)
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), hex(offset)
    assert read(MODE_PC, 4).hex() == data['bytecode_binding']['bytes_hex']
    return dict(upstream=result, additional_instructions=len(EXPECTED), additional_bytecode_words=1)


def build(path, libc, *, on_case=None):
    data = dict(schema='vm9-native-171-mode-read-20261118-v1',
        provenance=dict(Metasec_sha256=handoff.inputs.SHA256,
            Bionic_sha256=handoff.inputs.LIBC_SHA256, upstream_prelude_evidence=prelude.EVIDENCE.name),
        boundary=BOUNDARY, claims=CLAIMS, limits=LIMITS, providers=handoff.inputs.PROVIDERS,
        Android_execution=False, synthetic_memory_only=True,
        static_instruction_bindings=[dict(offset=hex(a), mnemonic=m, operands=s) for a,m,s in EXPECTED],
        bytecode_binding=dict(offset=hex(MODE_PC), bytes_hex='01400203'), case_results=[])
    verify_elf(data, path)
    data['case_results'] = replay(path, libc, on_case=on_case)
    validate(data)
    return data


def negatives(data):
    damaged = []
    for key, value in CLAIMS.items():
        bad = deepcopy(data); bad['claims'][key] = not value; damaged.append(bad)
    for index in range(len(controls())):
        for key, value in (('stored_R1', '0x138'), ('packed_context_reads', 1),
            ('context_object_reads', 1), ('stopped_before_next_bytecode_fetch', False)):
            bad = deepcopy(data); bad['case_results'][index][key] = value; damaged.append(bad)
        for key, value in (('size', 8), ('packed_offset', 32), ('bytes_hex', '38010000')):
            bad = deepcopy(data); bad['case_results'][index]['reads'][0][key] = value; damaged.append(bad)
        bad = deepcopy(data); bad['case_results'][index]['decoded_load']['base_register'] = 3; damaged.append(bad)
    bad = deepcopy(data); bad['bytecode_binding']['bytes_hex'] = '01400202'; damaged.append(bad)
    for bad in damaged:
        try:
            validate(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError('damaged mode-read evidence accepted')
    return len(damaged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path); parser.add_argument('--libc', type=Path)
    parser.add_argument('--replay', action='store_true'); args = parser.parse_args()
    if args.replay and (not args.elf or not args.libc):
        parser.error('--replay requires --elf and --libc')
    data = json.loads(EVIDENCE.read_text(encoding='utf-8')); validate(data)
    result = dict(retained_synthetic_cases=len(controls()), damaged_evidence_rejected=negatives(data),
        mode_bytecode=hex(MODE_PC), stored_R1='0x171', packed_context_read_observed=False,
        complete_standalone_signer_verified=False)
    if args.elf:
        result['Metasec_bindings'] = verify_elf(data, args.elf)
    if args.libc:
        handoff.inputs.libc_image(args.libc); result['matching_Bionic_digest_verified'] = True
    if args.replay:
        assert replay(args.elf, args.libc) == data['case_results'], 'frozen mode-read replay differs'
        result['original_code_cases_replayed'] = len(controls())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
