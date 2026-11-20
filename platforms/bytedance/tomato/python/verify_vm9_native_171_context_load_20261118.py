"""Bounded constructed 0x171 request through synthetic JNI to a handler load.

Reuses the accepted stack evaluator service contract for two explicit NULL
scenarios. One CPU keeps the original constructor and ordinary request state.
The observation sentinel stops after the first context load/store, without
claiming callback return, real Android stack identity, or signing output.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_constructed_graph_20261118 as graph
import verify_vm9_outer_signer_native as outer
import verify_vm9_request_stack_evaluator_fresh_20261012 as stack

EVIDENCE = graph.EVIDENCE.with_name('vm9_native_171_context_load_20261118.json')
SLOTS = (0x30, 0x388, 0x720, 0xB8)
INHERITED_SYSCALLS = (48,56,57,63,79,80,98,167,198,214,215,222,226,233)
AID_CACHE_PROFILE = dict(
    name='synthetic_aid_absent_cache', URL=graph.inputs.URL+b'?aid=1',
    native_pc=0x271DBC, bytecode=0xFCA40, number=48,
    dirfd_u32=0xFFFFFF9C, pathname=b'/data/local/tmp/bdms/mssdk/ml/', mode=4, flags=0,
)
AID_DIRECTORY_PROFILE = dict(
    name='synthetic_aid_absent_directory', URL=AID_CACHE_PROFILE['URL'],
    stat_paths=(b'/data/local/tmp/bdms/mssdk/ml', b'/data'), stat_buffer_size=128,
    stat_return_pc=0x272D68,
)
AID_FILE_PROFILE = dict(
    name='synthetic_aid_absent_cache_file', URL=AID_CACHE_PROFILE['URL'],
    pathname=AID_CACHE_PROFILE['pathname']+b'/.msp_'+hashlib.sha1(b'def').hexdigest().encode(),
    return_pc=0x27308C, maximum_main_SVCs=4,
)
NULL_PAYLOAD_READ_PROFILE = dict(
    name='constructed_null_payload', bytecode=0xFCD04, member_offset=8,
    virtual_register=2, value=0, maximum_handler_reads=2,
)
LOAD, STORE, STOP = 0x16F96C, 0x16F974, 0x16F978
CURSOR, WORD = 0xFAE4C, 0x10820418
EXPECTED = [
    (0x28B714, 'ldr', 'x8, [x0]'), (0x28B718, 'ldr', 'x8, [x8, #0x30]'),
    (0x28B71C, 'blr', 'x8'), (0x28BFC0, 'and', 'w8, w0, #1'),
    (0x16F958, 'ldr', 'x12, [x28, x10, lsl #3]'),
    (0x16F95C, 'sxth', 'x13, w11'), (LOAD, 'ldr', 'x9, [x12, x13]'),
    (STORE, 'str', 'x9, [x28, x14, lsl #3]'),
    (STOP, 'ldr', 'w9, [x8, #4]!'),
]
PROVIDERS = dict(
    inherited_outer=graph.PROVIDERS,
    JNI_owner='verify_vm9_request_stack_evaluator_fresh_20261012.py:Services.jni',
    JNI_environment_adapter='validate outer environment, translate only its ABI identity',
    JNI_slots=[hex(slot) for slot in SLOTS],
    main_import_names=['memset', '__cxa_atexit'],
    main_import_targets='resolved matching Bionic exports',
    permitted_libc_SVC_numbers=list(INHERITED_SYSCALLS),
    scenarios=['NULL_class0', 'NULL_static_id'],
    stop='observer stops after context store and moves PC to the oracle sentinel; no function return',
)
CLAIMS = dict(
    same_CPU_constructed_handler_to_ordinary_request=True,
    original_stack_evaluator_returned_under_explicit_NULL_scenarios=True,
    first_observed_handler_read_is_member_0x50=True,
    original_load_and_virtual_register_store_executed=True,
    constructed_handler_bytes_unchanged_at_stop=True,
    original_outer_postconditions_passed=True,
    real_JVM_or_successful_Java_stack_inspection_verified=False,
    complete_handler_or_service_semantics_verified=False,
    callback_return_serialization_or_success_cleanup_verified=False,
    whole_request_native_Python_differential_verified=False,
    ordinary_Cronet_six_headers_verified=False,
    complete_standalone_signer_verified=False,
    Android_execution=False, online_acceptance_verified=False,
)


def controls():
    return [dict(base=base, property_profile='absent', null_at=profile)
            for base in graph.BASES for profile in ('class0', 'static_id')]


class _TraceAccumulator:
    """Keep graph.digest's JSON bytes while allowing a large trace to drain."""

    def __init__(self):
        self.items = []
        self._hash = None
        self.count = 0

    @staticmethod
    def _encode(item):
        return json.dumps(item, separators=(',', ':'), sort_keys=True).encode()

    def append(self, item):
        if self._hash is None:
            self.items.append(item)
        else:
            if self.count:
                self._hash.update(b',')
            self._hash.update(self._encode(item))
        self.count += 1

    def compact(self):
        if self._hash is not None:
            return
        self._hash = hashlib.sha256(b'[')
        for index, item in enumerate(self.items):
            if index:
                self._hash.update(b',')
            self._hash.update(self._encode(item))
        self.items.clear()

    def digest(self, extra=()):
        if self._hash is None:
            return graph.digest(self.items + list(extra))
        digest = self._hash.copy()
        for index, item in enumerate(extra, self.count):
            if index:
                digest.update(b',')
            digest.update(self._encode(item))
        digest.update(b']')
        return digest.hexdigest()

    def __len__(self):
        return self.count


def replay(path, libc, *, on_case=None, case_controls=None, _extension_factory=None,
           _request_profile=None, _handler_read_profile=None):
    from unicorn import arm64_const as arm
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    assert _request_profile in (None, AID_CACHE_PROFILE['name'], AID_DIRECTORY_PROFILE['name'], AID_FILE_PROFILE['name']), 'unknown request profile'
    aid_cache = _request_profile is not None
    aid_file = _request_profile == AID_FILE_PROFILE['name']
    assert _handler_read_profile in (None, NULL_PAYLOAD_READ_PROFILE['name']), 'unknown handler read profile'
    null_payload = _handler_read_profile is not None
    assert not null_payload or (aid_file and _extension_factory is not None), 'second handler read requires the file profile and observer'
    aid_directory = aid_file or _request_profile == AID_DIRECTORY_PROFILE['name']
    assert not aid_cache or _extension_factory is not None, 'aid cache profile requires an explicit observer'
    request_URL = AID_CACHE_PROFILE['URL'] if aid_cache else graph.inputs.URL
    _, main_loads, read_main = graph.inputs.load_elf(path)
    libc_elf, _ = graph.inputs.libc_image(libc)
    libc_bytes = [(s['p_vaddr'], s.data()) for s in libc_elf.iter_segments() if s['p_type']=='PT_LOAD']
    spans = [(s['p_vaddr'], s['p_vaddr']+s['p_memsz']) for s in main_loads if s['p_flags'] & 1]
    libc_spans = [(s['p_vaddr'], s['p_vaddr']+s['p_memsz']) for s in libc_elf.iter_segments()
                  if s['p_type']=='PT_LOAD' and s['p_flags'] & 1]
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    for control in controls() if case_controls is None else case_controls:
        image = control['base']
        state = dict(continued=False, request_started=False, stored=False, store_verified=False)
        extension = None if _extension_factory is None else _extension_factory(control)
        service = stack.Services(image, {}, dict(null_at=control['null_at']))
        target_slots=tuple(SLOTS)+tuple(getattr(extension,'extra_jni_slots',()))
        assert len(set(target_slots))==len(target_slots)
        targets = {slot:graph.SCRATCH+0x800+i*16 for i,slot in enumerate(target_slots)}
        trace, code, jni, reads, returns, syscalls, main_syscalls = _TraceAccumulator(), {}, [], [], [], [], []
        trace_window_start=[0];closed_trace_windows=[]

        def trace_digest(extra=()):
            return trace.digest(extra)

        def maybe_compact_trace():
            if extension is not None and getattr(extension, 'compact_trace_requested', False):
                trace.compact()
                extension.compact_trace_requested = False

        def reg(cpu, name):
            return cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+name.upper()))

        def word(cpu, address, size=8):
            return int.from_bytes(cpu.mem_read(address,size),'little')

        def call(cpu, slot):
            args = tuple(reg(cpu,'x'+str(i)) for i in range(stack.COUNTS[slot]))
            late_handler = (getattr(extension, 'late_jni', None)
                            if extension is not None else None)
            if late_handler is not None:
                handled, result = late_handler(cpu, slot, args, state)
                if handled:
                    return result
            if args[0] != outer.io.GUEST+0x7800 or not state.get('evaluator_active',False):
                pc=reg(cpu,'pc');lr=reg(cpu,'x30')
                dispatcher=None
                if extension is not None:
                    counts=getattr(extension,'_post_syscall_pc_counts',{})
                    dispatcher=dict(
                        observed_pc_counts={hex(offset):count for offset,count in counts.items()
                                            if offset in (0x16855C,0x16D8B8,0x16974C)},
                        distinct_dispatch_states=len(getattr(extension,'_post_syscall_dispatch_state_counts',{})),
                        first_stream_cursor=(hex(extension._post_syscall_cursor_first)
                            if getattr(extension,'_post_syscall_cursor_first',None) is not None else None),
                        last_stream_cursor=(hex(extension._post_syscall_cursor_last)
                            if getattr(extension,'_post_syscall_cursor_last',None) is not None else None),
                        monotonic_cursor_steps=getattr(extension,'_post_syscall_cursor_monotonic_steps',None),
                        bound_pc_state=getattr(extension,'_post_syscall_dispatch_stop',None))
                diagnostic=dict(
                    slot=hex(slot),args=[hex(value) for value in args],
                    expected_env=hex(outer.io.GUEST+0x7800),
                    interface_table_pointer=hex(word(cpu,outer.io.GUEST+0x7800)),
                    pc=hex(pc),pc_offset=hex(pc-image) if image<=pc<image+0x400000 else None,
                    lr=hex(lr),lr_offset=hex(lr-image) if image<=lr<image+0x400000 else None,
                    evaluator_active=state.get('evaluator_active',False),
                    evaluator_return_pc=(hex(state['evaluator_return_pc'])
                        if state.get('evaluator_return_pc') is not None else None),
                    request_started=state.get('request_started',False),
                    PC_slot=(hex(state['PC_slot']) if state.get('PC_slot') is not None else None),
                    PC_slot_value=(hex(word(cpu,state['PC_slot'])) if state.get('PC_slot') is not None else None),
                    instruction_observations=len(trace),
                    main_image_svc_count=len(main_syscalls),
                    last_main_image_svc=main_syscalls[-1] if main_syscalls else None,
                    last_libc_svc=syscalls[-1] if syscalls else None,
                    gettimeofday_entered=(getattr(extension,'_gettimeofday_entered',None)
                        if extension is not None else None),
                    dispatcher_diagnostics=dispatcher)
                raise AssertionError('continuation JNI provider contract violation: '+
                                     json.dumps(diagnostic,sort_keys=True))
            result = service.jni(stack.G+0xF600+slot//2, (stack.h.ENV,*args[1:]),
                lambda a,n:bytes(cpu.mem_read(a,n)), cpu.mem_write)
            assert result in (0, stack.h.CLS)
            if slot in (0x388,0xB8): assert args[1] == stack.h.CLS
            event = dict(slot=hex(slot), result='class_fixture' if result else 'NULL_or_false',
                         caller=hex(reg(cpu,'x30')-image))
            if slot == 0x30:
                name = bytearray()
                for index in range(1024):
                    value = cpu.mem_read(args[1]+index,1)
                    if value == b'\0': break
                    name.extend(value)
                else: raise AssertionError('unbounded FindClass name')
                event.update(name_length=len(name),name_sha256=hashlib.sha256(name).hexdigest())
            jni.append(event)
            return result

        def terminal(cpu, *, root, wrapper, **unused):
            child=word(cpu,root+0x18);pair=word(cpu,child+0x20);context=word(cpu,pair+8)
            assert word(cpu,pair)==image+graph.CALLBACK and word(cpu,context)==image+0x35DC50
            assert word(cpu,image+0x3E0950)==word(cpu,image+0x3E0960,1)==0
            assert all(word(cpu,context+off) and word(cpu,context+off+8)
                       and word(cpu,word(cpu,context+off+8),4)>0 for off in (0x30,0x40,0x50,0x60))
            state.update(root=root,wrapper=wrapper,context=context,
                handler_bytes=bytes(cpu.mem_read(context,0x80)),
                expected_payload=word(cpu,context+0x50),counter=word(cpu,context+0x58),
                counter_before=word(cpu,word(cpu,context+0x58),4))
            if extension is not None:
                state['allocator_events_ref']=unused['allocator_events']
            assert not any(start<graph.SCRATCH+4096 and graph.SCRATCH<=end for start,end,_ in cpu.mem_regions())
            cpu.mem_map(graph.SCRATCH,4096)
            cpu.mem_write(graph.SCRATCH+0x100,request_URL+b'\0')
            cpu.mem_write(graph.SCRATCH+0x200,b'x-test\r\nvalue\r\n\0')
            cpu.mem_write(graph.SCRATCH,(graph.SCRATCH+0x100).to_bytes(8,'little')
                          +(graph.SCRATCH+0x200).to_bytes(8,'little'))
            table=word(cpu,outer.io.GUEST+0x7800)
            for slot,target in targets.items(): cpu.mem_write(table+slot,target.to_bytes(8,'little'))
            for i,value in enumerate((graph.SCRATCH,0,0)):
                cpu.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),value)
            cpu.reg_write(arm.UC_ARM64_REG_SP,outer.h.TOP)
            cpu.reg_write(arm.UC_ARM64_REG_X30,outer.oracle.STOP)
            cpu.reg_write(arm.UC_ARM64_REG_PC,image+0x27ED14)
            state['continued']=True
            return True

        def read(cpu,address,size):
            if not state['continued']: return
            if extension is not None and getattr(extension,'suppress_handler_read_observation',False): return
            if null_payload and len(reads)>=NULL_PAYLOAD_READ_PROFILE['maximum_handler_reads']:
                return
            context=state['context']
            if address<context+0x80 and context<address+size:
                if null_payload and reads:
                    profile=NULL_PAYLOAD_READ_PROFILE
                    assert len(reads)==1 and reg(cpu,'pc')==image+LOAD, (
                        f"second handler read count or site: reads={len(reads)} "
                        f"pc={hex(reg(cpu,'pc'))} expected={hex(image+LOAD)} "
                        f"address={hex(address)} size={size} context={hex(context)} "
                        f"x12={hex(reg(cpu,'x12'))} x13={hex(reg(cpu,'x13'))} "
                        f"x14={hex(reg(cpu,'x14'))} first={reads!r}")
                    assert word(cpu,state['PC_slot'])==image+profile['bytecode']
                    assert address==context+profile['member_offset'] and size==8
                    assert reg(cpu,'x12')==context and reg(cpu,'x13')==profile['member_offset']
                    assert reg(cpu,'x14')==profile['virtual_register']
                    assert word(cpu,address)==int.from_bytes(state['handler_bytes'][8:16],'little')==profile['value']
                    reads.append(dict(native_pc=hex(LOAD),bytecode=hex(profile['bytecode']),member_offset='0x8',
                        size=8,virtual_register=2,value_u64=0,base_is_constructed_handler=True,
                        value_is_constructor_member_payload=True))
                    return
                assert not reads and reg(cpu,'pc')==image+LOAD
                assert word(cpu,state['PC_slot'])==image+CURSOR
                assert address==context+0x50 and size==8
                assert reg(cpu,'x12')==context and reg(cpu,'x13')==0x50
                assert word(cpu,address)==state['expected_payload']
                state['destination_register']=reg(cpu,'x14')
                reads.append(dict(native_pc=hex(LOAD),bytecode=hex(CURSOR),member_offset='0x50',
                                  size=8,base_is_constructed_handler=True,
                                  value_is_constructor_member_payload=True))

        def observe(cpu,pc):
            if not state['continued']: return
            offset=pc-image
            if extension is not None:
                pre_observe=getattr(extension,'pre_observe',None)
                if pre_observe is not None and pre_observe(cpu,pc,state):
                    maybe_compact_trace()
                    return
            if (null_payload and offset==LOAD and reg(cpu,'x12')==state['context']
                    and word(cpu,state['PC_slot'])==image+NULL_PAYLOAD_READ_PROFILE['bytecode']):
                assert len(reads)==1 and 'second_handler_read_prefix' not in state
                # The retained old stop counted this observed LDR before its
                # execution. Reproduce that trace convention for comparison.
                state['second_handler_read_prefix']=dict(
                    context_reads=list(reads),evaluator_returns=list(returns),JNI_calls=list(jni),
                    libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                    instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',LOAD]]),
                    code_sha256=graph.digest([[*site,raw] for site,raw in sorted(code.items())]))
            if (null_payload and offset==0x16EE38 and word(cpu,state['PC_slot'])==image+0xFD064):
                assert 'null_branch_prefix' not in state
                observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                state['null_branch_prefix']=dict(
                    context_reads=list(reads),evaluator_returns=list(returns),JNI_calls=list(jni),
                    libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                    instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                    code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
            if extension is not None:
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD0D4):
                    assert 'client_key_name_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['client_key_name_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD140):
                    assert 'client_key_lookup_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['client_key_lookup_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]),
                        client_key_name_prefix=state['client_key_name_prefix'])
                if (null_payload and offset==0x16A5E8 and word(cpu,state['PC_slot'])==image+0xFD180):
                    assert 'client_key_result_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['client_key_result_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]),
                        client_key_lookup_prefix=state['client_key_lookup_prefix'])
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD228):
                    assert 'kmsv_lookup_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['kmsv_lookup_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]),
                        client_key_result_prefix=state['client_key_result_prefix'])
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD258):
                    assert 'kmsv_scope_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['kmsv_scope_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD290):
                    assert 'kmsv_scope_exit_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['kmsv_scope_exit_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD2B4):
                    assert 'contained_reference_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['contained_reference_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD2DC):
                    assert 'configuration_clone_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_clone_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD38C):
                    assert 'configuration_cleanup_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_cleanup_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD424):
                    assert 'configuration_owner_cleanup_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_owner_cleanup_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD5B8):
                    assert 'configuration_hash64_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_hash64_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD5E8):
                    assert 'configuration_tls_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_tls_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD628):
                    assert 'configuration_tls_store_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_tls_store_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA4C and word(cpu,state['PC_slot'])==image+0xFD694):
                    assert 'configuration_copy56_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_copy56_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x16AA48 and word(cpu,state['PC_slot'])==image+0xFD6B0):
                    assert 'configuration_suffix_call_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['configuration_suffix_call_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                if (null_payload and offset==0x286CE8 and word(cpu,state['PC_slot'])==image+0xFD6B0):
                    assert 'suffix_constants_prefix' not in state
                    observed_code=dict(code);observed_code[('metasec',offset)]=read_main(offset,4).hex()
                    state['suffix_constants_prefix']=dict(
                        JNI_calls=list(jni),libc_SVC_boundaries=list(syscalls),main_image_SVC_boundaries=list(main_syscalls),
                        instruction_observations=len(trace)+1,trace_sha256=trace_digest([['metasec',offset]]),
                        code_sha256=graph.digest([[*site,raw] for site,raw in sorted(observed_code.items())]))
                extension.observe(cpu,pc,state)
            if offset==STOP and state['stored'] and not state['store_verified']:
                destination=state['destination_register']
                assert word(cpu,state['backing']+destination*8)==state['expected_payload']
                assert word(cpu,state['PC_slot'])==image+CURSOR
                assert bytes(cpu.mem_read(state['context'],0x80))==state['handler_bytes']
                state['counter_after']=word(cpu,state['counter'],4)
                state['store_verified']=True
                if extension is None:
                    # Default observation terminal; the callback has not returned.
                    # No native instruction is patched.
                    cpu.emu_stop()
                    cpu.reg_write(arm.UC_ARM64_REG_PC,outer.oracle.STOP)
                    return
                extension.member_boundary(cpu,state,dict(
                    instruction_observations=len(trace),trace_sha256=trace_digest(),
                    code_sha256=graph.digest([[*site,raw] for site,raw in sorted(code.items())])))
            if pc in targets.values():
                slot=next(slot for slot,target in targets.items() if pc==target)
                trace.append(['JNI_provider',slot])
                return
            domain,local='metasec',offset
            if graph.inputs.LIBC_BASE<=pc<graph.inputs.LIBC_BASE+0x200000:
                domain,local='libc',pc-graph.inputs.LIBC_BASE
                start,raw=next((s,b) for s,b in libc_bytes if s<=local and local+4<=s+len(b))
                original=raw[local-start:local-start+4]
            else: original=read_main(offset,4)
            assert bytes(cpu.mem_read(pc,4))==original
            site=(domain,local)
            if site not in code:
                instruction,=decoder.disasm(original,local)
                assert instruction.mnemonic not in ('hvc','smc','brk','hlt')
                if instruction.mnemonic=='svc':
                    assert instruction.op_str=='#0'
                    assert domain=='libc' or (aid_cache and local==AID_CACHE_PROFILE['native_pc'])
                code[site]=original.hex()
            if original==b'\x01\x00\x00\xd4':
                number=reg(cpu,'x8')
                if domain=='libc':
                    assert number in INHERITED_SYSCALLS
                    syscalls.append(dict(libc_pc=hex(local),number=number))
                else:
                    binding=AID_CACHE_PROFILE
                    file_call=aid_file and len(main_syscalls)==3
                    if aid_file:
                        assert len(main_syscalls)<AID_FILE_PROFILE['maximum_main_SVCs'], 'cache file SVC count exceeded'
                    if file_call:
                        binding=dict(binding,pathname=AID_FILE_PROFILE['pathname'])
                        assert reg(cpu,'x30')==image+AID_FILE_PROFILE['return_pc']
                    elif aid_directory:
                        assert len(main_syscalls)<=len(AID_DIRECTORY_PROFILE['stat_paths']), 'directory SVC count exceeded'
                        if main_syscalls:
                            binding=dict(binding,number=79,
                                pathname=AID_DIRECTORY_PROFILE['stat_paths'][len(main_syscalls)-1])
                    else:
                        assert aid_cache and not main_syscalls
                    assert local==binding['native_pc'] and number==binding['number']
                    assert word(cpu,state['PC_slot'])==image+binding['bytecode']
                    assert reg(cpu,'x0')==binding['dirfd_u32']
                    assert outer.io.cstring(cpu,reg(cpu,'x1'))==binding['pathname']
                    assert reg(cpu,'x3')==binding['flags']
                    event=dict(native_pc=hex(local),bytecode=hex(binding['bytecode']),
                        number=number,dirfd_u32=binding['dirfd_u32'],flags=binding['flags'],
                        pathname_length=len(binding['pathname']),
                        pathname_sha256=hashlib.sha256(binding['pathname']).hexdigest())
                    if number==48:
                        assert reg(cpu,'x2')==binding['mode']
                        event['mode']=binding['mode']
                        if file_call:event['return_pc']=hex(AID_FILE_PROFILE['return_pc'])
                    else:
                        size=AID_DIRECTORY_PROFILE['stat_buffer_size'];buffer=reg(cpu,'x2')
                        assert aid_directory and number==79
                        assert outer.h.STACK<=buffer and buffer+size<=outer.h.STACK+outer.h.STACK_BYTES
                        assert buffer==reg(cpu,'sp')+0x58
                        assert reg(cpu,'x30')==image+AID_DIRECTORY_PROFILE['stat_return_pc']
                        event.update(stat_buffer_in_native_stack=True,stat_buffer_size=size,
                            stat_buffer_SP_offset=0x58,return_pc=hex(AID_DIRECTORY_PROFILE['stat_return_pc']))
                    main_syscalls.append(event)
            if state.pop('start_new_instruction_window',False):
                closed_trace_windows.append(len(trace)-trace_window_start[0])
                trace_window_start[0]=len(trace)
            trace.append([domain,local])
            window_observations=len(trace)-trace_window_start[0]
            window_limit=getattr(extension,'instruction_window_limit',400000)
            if window_observations>=window_limit:
                diagnostic=getattr(extension,'instruction_window_diagnostics',None)
                detail='; '+diagnostic() if diagnostic is not None else ''
                raise AssertionError('continuation instruction-window bound'+detail)
            if offset==graph.CALLBACK:
                assert reg(cpu,'x2')==0x171 and reg(cpu,'x3')==state['context']
                assert all(word(cpu,word(cpu,reg(cpu,'x'+str(i))+8),4)==3 for i in (0,1))
            if offset==0x283130:
                state['packed']=reg(cpu,'x1');state['request_started']=True
                assert word(cpu,state['packed']+0x18,4)==0x171
                assert word(cpu,state['packed']+0x20)==state['context']
            if state['request_started'] and offset==0x1684F0 and 'PC_slot' not in state:
                state.update(PC_slot=reg(cpu,'x19'),backing=reg(cpu,'x28'))
                assert word(cpu,state['PC_slot'])==image+0xF7720
            if offset==0x28B05C:
                assert not returns
                state.update(evaluator_return_pc=reg(cpu,'x30'),evaluator_active=True)
            if pc==state.get('evaluator_return_pc'):
                assert state['evaluator_active'] and reg(cpu,'x0')==0
                returns.append(dict(native_pc=hex(offset),result=0))
                state['evaluator_active']=False
            if offset==STORE and reads and not state['stored']:
                assert not state['stored'] and reg(cpu,'x9')==state['expected_payload']
                state['stored']=True
            if state['request_started'] and offset in (0x347F60,0x348410):
                read(cpu,reg(cpu,'x1'),reg(cpu,'x2'))

        def writes(cpu,address,size):
            assert not any(address<image+end and image+start<address+size for start,end in spans)
            assert not any(address<graph.inputs.LIBC_BASE+end
                           and graph.inputs.LIBC_BASE+start<address+size for start,end in libc_spans)

        result=outer.case(path,libc,image,None,terminal_continuation=terminal,
            execution_observer=observe,continuation_memory_read_observer=read,
            continuation_memory_write_observer=writes,
            continuation_main_import_names=('memset','__cxa_atexit'),
            continuation_references=(getattr(extension,'continuation_references',())
                                     if extension is not None else ()),
            continuation_reference_types=(getattr(extension,'continuation_reference_types',{})
                                          if extension is not None else {}),
            unmapped_observer=(getattr(extension,'observe_unmapped',None)
                               if extension is not None else None),
            _native_runner=None if extension is None else extension.native_runner,
            continuation_host_imports={target-image:(lambda cpu,slot=slot:call(cpu,slot))
                                       for slot,target in targets.items()})
        assert state['store_verified'] and len(returns)==1
        assert len(reads)==(NULL_PAYLOAD_READ_PROFILE['maximum_handler_reads'] if null_payload else 1)
        assert result['virtual_descriptors_not_executed']
        if extension is not None:
            row=extension.finish(result,state,dict(
                context_reads=reads,evaluator_returns=returns,JNI_calls=jni,
                libc_SVC_boundaries=syscalls,instruction_observations=len(trace),
                main_image_SVC_boundaries=main_syscalls,
                **({'instruction_observation_windows':closed_trace_windows+[len(trace)-trace_window_start[0]]}
                   if closed_trace_windows else {}),
                **({'second_handler_read_prefix':state['second_handler_read_prefix']} if null_payload else {}),
                **({'null_branch_prefix':state['null_branch_prefix']} if 'null_branch_prefix' in state else {}),
                **({'client_key_name_prefix':state['client_key_name_prefix']} if 'client_key_name_prefix' in state else {}),
                **({'client_key_lookup_prefix':state['client_key_lookup_prefix']} if 'client_key_lookup_prefix' in state else {}),
                **({'client_key_result_prefix':state['client_key_result_prefix']} if 'client_key_result_prefix' in state else {}),
                **({'kmsv_lookup_prefix':state['kmsv_lookup_prefix']} if 'kmsv_lookup_prefix' in state else {}),
                **({'kmsv_scope_prefix':state['kmsv_scope_prefix']} if 'kmsv_scope_prefix' in state else {}),
                **({'kmsv_scope_exit_prefix':state['kmsv_scope_exit_prefix']} if 'kmsv_scope_exit_prefix' in state else {}),
                **({'contained_reference_prefix':state['contained_reference_prefix']} if 'contained_reference_prefix' in state else {}),
                **({'configuration_clone_prefix':state['configuration_clone_prefix']} if 'configuration_clone_prefix' in state else {}),
                **({'configuration_cleanup_prefix':state['configuration_cleanup_prefix']} if 'configuration_cleanup_prefix' in state else {}),
                **({'configuration_owner_cleanup_prefix':state['configuration_owner_cleanup_prefix']} if 'configuration_owner_cleanup_prefix' in state else {}),
                **({'configuration_hash64_prefix':state['configuration_hash64_prefix']} if 'configuration_hash64_prefix' in state else {}),
                **({'configuration_tls_prefix':state['configuration_tls_prefix']} if 'configuration_tls_prefix' in state else {}),
                **({'configuration_tls_store_prefix':state['configuration_tls_store_prefix']} if 'configuration_tls_store_prefix' in state else {}),
                **({'configuration_copy56_prefix':state['configuration_copy56_prefix']} if 'configuration_copy56_prefix' in state else {}),
                **({'configuration_suffix_call_prefix':state['configuration_suffix_call_prefix']} if 'configuration_suffix_call_prefix' in state else {}),
                **({'suffix_constants_prefix':state['suffix_constants_prefix']} if 'suffix_constants_prefix' in state else {}),
                trace_sha256=trace_digest(),
                code_sha256=graph.digest([[*site,raw] for site,raw in sorted(code.items())])))
            rows.append(row)
            if on_case is not None:on_case(row)
            continue
        row=dict(control=control,observation_stop_before=hex(STOP),
            oracle_PC_is_observation_sentinel=True,original_outer_postconditions_passed=True,
            handler_sha256=hashlib.sha256(state['handler_bytes']).hexdigest(),
            handler_bytes_unchanged=True,first_observed_context_read=reads[0],
            stored_virtual_register=state['destination_register'],stored_value_matches_member=True,
            member_counter_before=state['counter_before'],member_counter_after=state['counter_after'],
            evaluator_returns=returns,JNI_calls=jni,
            libc_SVC_boundaries=syscalls,
            continuation_instruction_observations=len(trace),
            continuation_trace_sha256=trace_digest(),
            continuation_code_sha256=graph.digest([[*site,raw] for site,raw in sorted(code.items())]),
            allocator_counts=result['actual_allocator_counts'],service_counts=result['explicit_service_counts'],
            allocation_ledger_sha256=graph.digest(result['allocator_events']),
            publication_ledger_sha256=graph.digest(result['publication_ledger']))
        rows.append(row)
        if on_case is not None:on_case(row)
    return rows


def validate(data):
    assert data['schema']=='vm9-native-171-context-load-20261118-v1'
    assert data['provenance']==dict(Metasec_sha256=graph.inputs.SHA256,
        Bionic_sha256=graph.inputs.LIBC_SHA256,constructor_owner='verify_vm9_outer_signer_native.py',
        stack_provider_owner=PROVIDERS['JNI_owner'])
    assert data['providers']==PROVIDERS and data['claims']==CLAIMS
    assert data['static_instruction_bindings']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert data['bytecode']==dict(offset=hex(CURSOR),word=hex(WORD))
    assert len(data['case_results'])==len(controls())
    for row,control in zip(data['case_results'],controls()):
        assert row['control']==control and row['observation_stop_before']==hex(STOP)
        for key in ('oracle_PC_is_observation_sentinel','original_outer_postconditions_passed',
                    'handler_bytes_unchanged','stored_value_matches_member'):assert row[key] is True
        assert row['first_observed_context_read']==dict(native_pc=hex(LOAD),bytecode=hex(CURSOR),
            member_offset='0x50',size=8,base_is_constructed_handler=True,value_is_constructor_member_payload=True)
        assert row['stored_virtual_register']==2
        assert row['member_counter_before']==row['member_counter_after']==2
        assert row['evaluator_returns']==[dict(native_pc='0x28bfc0',result=0)]
        slots=[event['slot'] for event in row['JNI_calls']]
        expected=['0x30','0x720'] if control['null_at']=='class0' else ['0x30','0x720','0x388','0xb8','0x720']
        assert slots==expected
        assert [e['result'] for e in row['JNI_calls']]==(
            ['NULL_or_false']*2 if control['null_at']=='class0' else ['class_fixture']+['NULL_or_false']*4)
        assert row['JNI_calls'][0]['name_length']==16
        assert row['JNI_calls'][0]['name_sha256']=='674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'
        assert row['continuation_instruction_observations']>180000
        assert row['libc_SVC_boundaries']==[
            dict(libc_pc='0x1bf1c',number=98),
            dict(libc_pc='0x6a550',number=226),dict(libc_pc='0x6a550',number=226)]
        assert row['service_counts']['virtual_pthread_create']==3
        for key in ('handler_sha256','continuation_trace_sha256','continuation_code_sha256',
                    'allocation_ledger_sha256','publication_ledger_sha256'):
            assert graph.inputs.is_digest(row[key])


def verify_elf(data,path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    upstream=json.loads(graph.EVIDENCE.read_text(encoding='utf-8'));graph.validate(upstream)
    result=graph.verify_elf(upstream,path)
    _,_,read=graph.inputs.load_elf(path);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for address,mnemonic,operands in EXPECTED:
        instruction,=decoder.disasm(read(address,4),address)
        assert (instruction.mnemonic,instruction.op_str)==(mnemonic,operands),hex(address)
    assert int.from_bytes(read(CURSOR,4),'little')==WORD
    return dict(upstream=result,additional_instructions=len(EXPECTED),additional_bytecode_words=1)


def build(path,libc,*,on_case=None):
    data=dict(schema='vm9-native-171-context-load-20261118-v1',
        provenance=dict(Metasec_sha256=graph.inputs.SHA256,Bionic_sha256=graph.inputs.LIBC_SHA256,
            constructor_owner='verify_vm9_outer_signer_native.py',stack_provider_owner=PROVIDERS['JNI_owner']),
        providers=PROVIDERS,claims=CLAIMS,
        static_instruction_bindings=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        bytecode=dict(offset=hex(CURSOR),word=hex(WORD)),case_results=[])
    verify_elf(data,path)
    data['case_results']=replay(path,libc,on_case=on_case)
    validate(data)
    return data


def negatives(data):
    damaged=[]
    for key,value in CLAIMS.items():
        bad=deepcopy(data);bad['claims'][key]=not value;damaged.append(bad)
    for index in range(len(controls())):
        for key,value in (('handler_bytes_unchanged',False),('stored_value_matches_member',False),
                          ('original_outer_postconditions_passed',False),('evaluator_returns',[]),
                          ('JNI_calls',[]),('observation_stop_before','0x2830c4'),
                          ('stored_virtual_register',3),('member_counter_after',0),('libc_SVC_boundaries',[])):
            bad=deepcopy(data);bad['case_results'][index][key]=value;damaged.append(bad)
        for key,value in (('member_offset','0x40'),('value_is_constructor_member_payload',False),('size',4)):
            bad=deepcopy(data);bad['case_results'][index]['first_observed_context_read'][key]=value;damaged.append(bad)
    bad=deepcopy(data);bad['providers']['JNI_slots']=[];damaged.append(bad)
    for bad in damaged:
        try:validate(bad)
        except AssertionError:pass
        else:raise AssertionError('damaged context-load evidence accepted')
    return len(damaged)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--replay',action='store_true');args=parser.parse_args()
    if args.replay and (not args.elf or not args.libc):parser.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_context_load_cases=len(controls()),damaged_evidence_rejected=negatives(data),
                complete_standalone_signer_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:graph.inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen context-load replay differs'
        result['original_code_cases_replayed']=len(controls())
    print(json.dumps(result))


if __name__=='__main__':main()
