"""Join native outer construction to ordinary 0x171 callback selection.

One Unicorn CPU owns construction and the later ordinary input conversion.
The callback body never executes. Explicit OS/JNI/virtual-thread/diagnostic
services are inherited from the older outer oracle, not the tag-only mode
verifier's provider profile. No live app, signer result or model differential.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_inputs_20261118 as inputs
import verify_vm9_native_171_vm_handoff_20261118 as handoff
import verify_vm9_outer_signer_native as outer

EVIDENCE = inputs.EVIDENCE.with_name('vm9_native_171_constructed_graph_20261118.json')
BASES = (0x122C0000, 0x775C205000)
SCRATCH, CALLBACK = 0x71000000, 0x2830C4
EXPECTED = [
    (0x27FBC0, 'bl', '#0x1658e4'), (0x27FBD4, 'bl', '#0x27c7dc'),
    (0x27FC00, 'bl', '#0x32d4f8'), (0x27C814, 'ldr', 'x8, [x19]'),
    (0x27C818, 'str', 'x8, [x20]'), (0x27C81C, 'ldr', 'x8, [x19, #8]'),
    (0x27C820, 'str', 'x8, [x20, #8]'), (0x27C830, 'str', 'w9, [x8]'),
]
BOUNDARY = dict(outer_getter='0x1658e4', ordinary_entry='0x27ed14',
    child_dispatcher='0x27dd04', stop_before=hex(CALLBACK), mode='0x171',
    outer_wrapper_slot='0x3d15d8', ordinary_cache='0x3e0950',
    ordinary_guard='0x3e0960', cache_copy='0x27c7dc', callback_pair_context_offset=8)
PROVIDERS = dict(
    inherited_owner='verify_vm9_outer_signer_native.py',
    actual_matching_Bionic_allocator=True, explicit_virtual_OS_and_JNI=True,
    virtual_threads_created=3, virtual_thread_bodies_executed=False,
    diagnostic_helpers_substituted=['0x26c858', '0x26c9d0'],
    Android_JVM_used=False, thread_id=137,
    clock_seconds=1791023800, clock_nanoseconds=500000000,
    ordinary_inputs='fresh synthetic CStrings in an isolated mapped page',
    root_child_context_or_cache_bytes_seeded_by_continuation=False)
CLAIMS = dict(constructor_to_ordinary_callback_selection_same_CPU_verified=True,
    ordinary_cache_populated_by_original_copy_from_constructed_wrapper=True,
    callback_context_is_constructor_produced_service_refs_handler=True,
    native_mode_171_and_three_count_input_references_preserved=True,
    native_input_snapshot_used_as_Python_model_input=False,
    ordinary_callback_body_or_request_VM_executed=False,
    complete_handler_semantics_or_live_identity_verified=False,
    request_context_operand_consumption_verified=False,
    callback_return_serialization_or_success_cleanup_verified=False,
    whole_request_native_Python_differential_verified=False,
    ordinary_cronet_six_heads_verified=False, complete_standalone_signer_verified=False,
    online_acceptance_verified=False)
LIMITS = [
    'The older outer oracle has explicit OS/JNI, deferred virtual-thread and diagnostic helper services',
    'This provider profile is distinct from the tag-only no-internal-stub mode-read controls',
    'Fresh inputs and native constructor output are retained on one CPU; no native bytes seed a Python model',
    'Four handler reference members are checked while live; their Java/business semantics are not inferred',
    'Execution stops before callback +0x2830c4; ordinary request bytecode and context consumption do not execute',
    'Background thread execution, concurrency, live JVM, Android and network validation are unverified',
]


def controls():
    return [dict(base=base, property_profile=profile) for base in BASES
            for profile in ('absent', 'sdk_30')]


def digest(value):
    return inputs.digest_json(value)


def replay(path, libc, *, on_case=None, case_controls=None):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from unicorn import arm64_const as arm
    _, main_loads, read_main = inputs.load_elf(path)
    libc_elf, _ = inputs.libc_image(libc)
    libc_bytes = [(s['p_vaddr'], s.data()) for s in libc_elf.iter_segments()
                  if s['p_type'] == 'PT_LOAD']
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    for control in controls() if case_controls is None else case_controls:
        image = control['base']
        state = dict(continued=False)
        trace, code, events, calls = [], {}, [], []
        spans = [(image+s['p_vaddr'], image+s['p_vaddr']+s['p_memsz'])
                 for s in main_loads if s['p_flags'] & 1]
        spans += [(inputs.LIBC_BASE+s['p_vaddr'], inputs.LIBC_BASE+s['p_vaddr']+s['p_memsz'])
                  for s in libc_elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1]

        def reg(cpu, name):
            return cpu.reg_read(getattr(arm, 'UC_ARM64_REG_'+name.upper()))

        def word(cpu, address, width=8):
            return int.from_bytes(cpu.mem_read(address, width), 'little')

        def terminal(cpu, *, root, wrapper, **unused):
            child = word(cpu, root+0x18)
            pair = word(cpu, child+0x20)
            context = word(cpu, pair+8)
            assert word(cpu, pair) == image+CALLBACK and word(cpu, context) == image+0x35DC50
            assert word(cpu, image+0x3D15D8) == wrapper and word(cpu, wrapper) == root
            assert word(cpu, image+0x3E0950) == word(cpu, image+0x3E0960, 1) == 0
            refs = []
            for field in (0x30, 0x40, 0x50, 0x60):
                payload, counter = word(cpu, context+field), word(cpu, context+field+8)
                assert payload and counter and word(cpu, counter, 4) > 0
                refs.append(dict(field=hex(field), payload_nonzero=True, counter_nonzero=True,
                                 count=word(cpu, counter, 4)))
            state.update(root=root, wrapper=wrapper, child=child, pair=pair, context=context,
                handler_references=refs, handler_sha256=hashlib.sha256(cpu.mem_read(context, 0x80)).hexdigest(),
                wrapper_count_before=word(cpu, word(cpu, wrapper+8), 4))
            assert not any(start < SCRATCH+4096 and SCRATCH <= end for start,end,_ in cpu.mem_regions())
            cpu.mem_map(SCRATCH, 4096)
            cpu.mem_write(SCRATCH+0x100, inputs.URL+b'\0')
            cpu.mem_write(SCRATCH+0x200, b'x-test\r\nvalue\r\n\0')
            cpu.mem_write(SCRATCH, (SCRATCH+0x100).to_bytes(8,'little')+(SCRATCH+0x200).to_bytes(8,'little'))
            for index, value in enumerate((SCRATCH, 0, 0)):
                cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(index)), value)
            cpu.reg_write(arm.UC_ARM64_REG_SP, outer.h.TOP)
            cpu.reg_write(arm.UC_ARM64_REG_X30, outer.oracle.STOP)
            cpu.reg_write(arm.UC_ARM64_REG_PC, image+0x27ED14)
            state['continued'] = True
            return True

        def observe(cpu, pc):
            if not state['continued']:
                return
            offset, domain, local = pc-image, 'metasec', pc-image
            assert offset != CALLBACK, 'callback body executed'
            if inputs.LIBC_BASE <= pc < inputs.LIBC_BASE+0x200000:
                domain, local = 'libc', pc-inputs.LIBC_BASE
                start, raw = next((s, data) for s,data in libc_bytes if s <= local and local+4 <= s+len(data))
                original = raw[local-start:local-start+4]
            else:
                original = read_main(offset, 4)
            assert bytes(cpu.mem_read(pc, 4)) == original
            site = (domain, local)
            if site not in code:
                ins, = decoder.disasm(original, local)
                assert ins.mnemonic not in ('svc', 'hvc', 'smc', 'brk', 'hlt'), site
                code[site] = original.hex()
            trace.append([domain, local])
            if offset in (0x27FBC0, 0x27FBD4, 0x27FC00):
                events.append(hex(offset))
            if offset == 0x27FBD4:
                assert reg(cpu, 'x0') == image+0x3E0950 and reg(cpu, 'x1') == state['wrapper']
            if offset == 0x27C824:
                assert word(cpu, image+0x3E0950) == state['root']
                assert word(cpu, image+0x3E0958) == word(cpu, state['wrapper']+8)
            if offset in (0x27E478, 0x27E6A8):
                assert offset == 0x27E6A8
                assert reg(cpu,'x9') == image+CALLBACK and reg(cpu,'x2') == 0x171
                assert reg(cpu,'x3') == state['context']
                assert word(cpu,image+0x3E0950) == state['root'] and word(cpu,image+0x3E0960,1) == 1
                count = word(cpu, word(cpu,state['wrapper']+8),4)
                assert count == state['wrapper_count_before']+1
                refs = [reg(cpu,'x0'), reg(cpu,'x1')]
                assert all(word(cpu,word(cpu,r+8),4) == 3 for r in refs)
                calls.append(dict(site=hex(offset), mode='0x171', context_is_constructed_handler=True,
                    URL_reference_count=3, tree_reference_count=3, cache_reference_count=count,
                    handler_unchanged=hashlib.sha256(cpu.mem_read(state['context'],0x80)).hexdigest()==state['handler_sha256']))

        def writes(cpu, address, size):
            assert not any(address < end and start < address+size for start,end in spans), 'executable write'

        def runner(*args, **kwargs):
            kwargs['stop_offset'] = CALLBACK
            return outer.oracle.native(*args, **kwargs)

        result = outer.case(path, libc, image, outer.PROFILES[control['property_profile']],
            terminal_continuation=terminal, execution_observer=observe,
            continuation_memory_write_observer=writes, _native_runner=runner)
        assert state['continued'] and len(calls) == 1 and calls[0]['handler_unchanged']
        assert events == ['0x27fbc0', '0x27fbd4', '0x27fc00']
        assert trace[-1] == ['metasec', 0x27E6A8]
        assert result['virtual_descriptors_not_executed'] and result['virtual_thread_entry_offsets'] == ['0x326a2c','0x3260a4','0x3260a4']
        row = dict(control=control, native_stop_before=hex(CALLBACK), calls=calls,
            cache_initially_zero=True, cache_copy_and_guard_events=events,
            handler_reference_members=state['handler_references'],
            constructor_handler_sha256=state['handler_sha256'],
            ordinary_instruction_observations=len(trace), ordinary_trace_sha256=digest(trace),
            ordinary_code_sha256=digest([[*site,raw] for site,raw in sorted(code.items())]),
            allocator_counts=result['actual_allocator_counts'], service_counts=result['explicit_service_counts'],
            allocation_ledger_sha256=digest(result['allocator_events']),
            publication_ledger_sha256=digest(result['publication_ledger']),
            original_outer_postconditions_passed=True, request_callback_instructions_executed=0)
        rows.append(row)
        if on_case is not None:
            on_case(row)
    return rows


def validate(data):
    assert data['schema'] == 'vm9-native-171-constructed-graph-20261118-v1'
    assert data['provenance'] == dict(Metasec_sha256=inputs.SHA256, Bionic_sha256=inputs.LIBC_SHA256,
        constructor_owner='verify_vm9_outer_signer_native.py',
        prior_graph_evidence='vm9_outer_graph_object_provenance_20261028.json')
    assert data['boundary'] == BOUNDARY and data['providers'] == PROVIDERS
    assert data['claims'] == CLAIMS and data['limits'] == LIMITS
    assert data['Android_execution'] is False and data['synthetic_inputs_only'] is True
    assert data['static_instruction_bindings'] == [dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert len(data['case_results']) == len(controls())
    for row,control in zip(data['case_results'], controls()):
        assert row['control'] == control and row['native_stop_before'] == hex(CALLBACK)
        assert row['cache_initially_zero'] and row['original_outer_postconditions_passed']
        assert row['request_callback_instructions_executed'] == 0
        assert row['cache_copy_and_guard_events'] == ['0x27fbc0','0x27fbd4','0x27fc00']
        assert row['calls'] == [dict(site='0x27e6a8',mode='0x171',context_is_constructed_handler=True,
            URL_reference_count=3,tree_reference_count=3,cache_reference_count=2,handler_unchanged=True)]
        assert [ref['field'] for ref in row['handler_reference_members']] == ['0x30','0x40','0x50','0x60']
        for ref in row['handler_reference_members']:
            assert ref['payload_nonzero'] and ref['counter_nonzero'] and ref['count'] > 0
        assert row['ordinary_instruction_observations'] == 10168
        assert row['service_counts']['virtual_pthread_create'] == 3
        for key in ('constructor_handler_sha256','ordinary_trace_sha256','ordinary_code_sha256',
                    'allocation_ledger_sha256','publication_ledger_sha256'):
            assert inputs.is_digest(row[key])


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    handoff_data = json.loads(handoff.EVIDENCE.read_text(encoding='utf-8'))
    handoff.validate(handoff_data)
    upstream = handoff.verify_elf(handoff_data,path)
    _,_,read = inputs.load_elf(path)
    decoder = Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for offset,mnemonic,operands in EXPECTED:
        ins, = decoder.disasm(read(offset,4),offset)
        assert (ins.mnemonic,ins.op_str) == (mnemonic,operands),hex(offset)
    return dict(upstream=upstream, additional_cache_instructions=len(EXPECTED))


def build(path,libc,*,on_case=None):
    data = dict(schema='vm9-native-171-constructed-graph-20261118-v1',
        provenance=dict(Metasec_sha256=inputs.SHA256,Bionic_sha256=inputs.LIBC_SHA256,
            constructor_owner='verify_vm9_outer_signer_native.py',
            prior_graph_evidence='vm9_outer_graph_object_provenance_20261028.json'),
        boundary=BOUNDARY,providers=PROVIDERS,claims=CLAIMS,limits=LIMITS,
        Android_execution=False,synthetic_inputs_only=True,
        static_instruction_bindings=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        case_results=[])
    verify_elf(data,path)
    data['case_results'] = replay(path,libc,on_case=on_case)
    validate(data)
    return data


def negatives(data):
    damaged = []
    for key,value in CLAIMS.items():
        bad=deepcopy(data);bad['claims'][key]=not value;damaged.append(bad)
    for index in range(len(controls())):
        for key,value in (('cache_initially_zero',False),('original_outer_postconditions_passed',False),
                          ('request_callback_instructions_executed',1)):
            bad=deepcopy(data);bad['case_results'][index][key]=value;damaged.append(bad)
        for key,value in (('context_is_constructed_handler',False),('mode','0x138'),
                          ('URL_reference_count',2),('handler_unchanged',False)):
            bad=deepcopy(data);bad['case_results'][index]['calls'][0][key]=value;damaged.append(bad)
    bad=deepcopy(data);bad['providers']['diagnostic_helpers_substituted']=[];damaged.append(bad)
    for bad in damaged:
        try:
            validate(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError('damaged constructed-graph evidence accepted')
    return len(damaged)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--replay',action='store_true');args=parser.parse_args()
    if args.replay and (not args.elf or not args.libc):
        parser.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_constructed_graph_cases=len(controls()),damaged_evidence_rejected=negatives(data),
        ordinary_callback_executed=False,complete_standalone_signer_verified=False)
    if args.elf:
        result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:
        inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen constructed-graph replay differs'
        result['original_code_cases_replayed']=len(controls())
    print(json.dumps(result))


if __name__=='__main__':
    main()
