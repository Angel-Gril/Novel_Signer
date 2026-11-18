"""Replay ordinary native input conversion and callback selection to VM entry.

All guest inputs and object graphs are synthetic. Original Metasec and matching
Bionic instructions execute with the input verifier's explicit memory providers.
Execution stops before +0x168324: no request bytecode, signer output or Android.
The wrapper comparison uses observed callback-boundary state as local model
input; it is not a fresh whole-request Python differential.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import verify_vm9_native_171_inputs_20261118 as inputs

EVIDENCE = inputs.EVIDENCE.with_name('vm9_native_171_vm_handoff_20261118.json')
G = inputs.GUEST
TLS = G + 0xD000
CHILD, MUTEX = G + 0x3100, G + 0x9000
REGISTRY, CONTROL, SENTINEL = G + 0x9300, G + 0x9340, G + 0x9380
FALLBACK, CONTEXT, OTHER_CONTEXT = G + 0x93C0, G + 0x9400, G + 0x9480
RANGES = [(0x27DD04, 0x27E798), (0x2830C4, 0x28315C), (0x28509C, 0x2850A8)]
EXPECTED = [
    (0x27E438, 'ldr', 'x8, [sp, #0x30]'), (0x27E444, 'ldr', 'x8, [x8]'),
    (0x27E468, 'ldr', 'w2, [sp, #0x1c]'), (0x27E470, 'ldr', 'x3, [x8, #8]'),
    (0x27E478, 'blr', 'x9'), (0x27E660, 'ldr', 'x8, [sp, #0x38]'),
    (0x27E66C, 'ldr', 'x8, [x8, #0x20]'), (0x27E670, 'ldr', 'x8, [x8]'),
    (0x27E694, 'ldr', 'w2, [sp, #0x1c]'), (0x27E69C, 'ldr', 'x8, [x8, #0x20]'),
    (0x27E6A0, 'ldr', 'x3, [x8, #8]'), (0x27E6A8, 'blr', 'x9'),
    (0x2830C4, 'stp', 'x29, x30, [sp, #-0x20]!'),
    (0x2830D0, 'sub', 'sp, sp, #1, lsl #12'), (0x2830D4, 'sub', 'sp, sp, #0x720'),
    (0x2830EC, 'stp', 'x8, x0, [sp, #8]'), (0x283100, 'str', 'w2, [sp, #0x20]'),
    (0x28310C, 'str', 'x1, [sp, #0x18]'), (0x283114, 'stp', 'x3, x9, [sp, #0x28]'),
    (0x28311C, 'add', 'x2, x2, #0x230'), (0x283120, 'add', 'x3, x3, #0x690'),
    (0x283124, 'add', 'x1, sp, #8'), (0x283128, 'xpaclri', ''),
    (0x28312C, 'stp', 'x8, x30, [sp, #0x38]'), (0x283130, 'bl', '#0x168324'),
    (0x28509C, 'adrp', 'x0, #0x283000'), (0x2850A0, 'add', 'x0, x0, #0xc4'),
    (0x2850A4, 'ret', ''),
]
BOUNDARY = dict(entry='0x27ed14', input_function='0x27f84c', child_dispatcher='0x27dd04',
    callback='0x2830c4', stop_before='0x168324', bytecode='0xf7720', mode='0x171',
    registry_call='0x27e478', fallback_call='0x27e6a8',
    handler_vtable_slot='0x68', handler_slot_getter='0x28509c',
    callback_x3_source='selected callback pair +0x08',
    fallback_pair_source='child +0x20', packed_user_context_offset='0x20',
    direct_VM_x3='image +0x35e690',
    packed_mode='low u32 at argument block +0x18; high u32 retains caller memory')
CLAIMS = dict(synthetic_original_input_dispatch_and_wrapper_path_verified=True,
    native_mode_171_preserved_to_packed_VM_arguments=True,
    selected_pair_context_preserved=True, wrapper_defined_spans_match_existing_Python_model=True,
    observed_callback_boundary_state_used_as_local_wrapper_model_input=True,
    VM_entry_prelude_or_request_bytecode_executed=False,
    callback_return_or_success_cleanup_verified=False,
    live_root_child_callback_identity_verified=False, full_service_handler_state_verified=False,
    actual_business_arguments_or_callback_execution_verified=False,
    native_171_and_Java_138_VM_equivalence_verified=False,
    whole_request_native_Python_differential_verified=False,
    ordinary_cronet_six_head_chain_verified=False, complete_standalone_signer_verified=False,
    original_signature_runtime_equivalence_verified=False, online_header_acceptance_verified=False)
LIMITS = [
    'Root/child graph, registry nodes, opaque contexts, TLS, mutexes and input text are synthetic',
    'The two context objects carry a known handler vtable tag only; their complete fields and semantic identity are not reconstructed',
    'Only the first selected callback is entered; registry iteration after callback return and fallback after an empty callback result are not exercised',
    'Matching Bionic runs uncontended mutex/comparison paths; explicit memory/allocation providers and their limitations are inherited from the input verifier',
    'Execution stops before the first instruction at VM entry +0x168324; no VM table, bytecode handler or signer output is validated',
    'The local wrapper comparison starts from observed callback-boundary memory/registers and compares defined packed/saved spans only',
    'No native JNI hook, Android action, real request or network validation is added',
]


def controls():
    profiles = ('fallback', 'registry', 'null_registry_fallback', 'null_then_registry', 'null_context', 'readers7')
    return [dict(base=base, profile=profile, delimiter_initialized=bool(index),
                 first_hex=inputs.URL.hex(), second_hex=b'x-test\r\nvalue\r\n'.hex(),
                 padding_byte=(0x5A, 0xD3, 0x80, 0x11, 0x7F, 0xE2)[n])
            for index, base in enumerate((0x10000000, 0x6000000000)) for n,profile in enumerate(profiles)]


def selected_context(control):
    return 0 if control['profile'] == 'null_context' else OTHER_CONTEXT if control['profile'] in ('registry', 'null_then_registry') else CONTEXT


def is_registry(control):
    return control['profile'] in ('registry', 'null_then_registry')


def prepare_graph(pages, control):
    from vm9_allocator import _write_span
    base, profile = control['base'], control['profile']
    def write(a,v,n=8): _write_span(pages,a,v.to_bytes(n,'little'))
    _write_span(pages,MUTEX,bytes(0x98))
    write(MUTEX+0x90, 7 if profile=='readers7' else 0, 4)
    for a,v in ((CHILD+8,MUTEX),(CHILD+0x10,REGISTRY),(CHILD+0x20,FALLBACK),
        (REGISTRY,base+0x35B828),(REGISTRY+0x20,CONTROL),(CONTROL,SENTINEL),(CONTROL+8,0),
        (SENTINEL,1),(SENTINEL+8,0),(SENTINEL+16,SENTINEL),(SENTINEL+24,SENTINEL),
        (FALLBACK,base+0x2830C4),(FALLBACK+8,0 if profile=='null_context' else CONTEXT),
        (CONTEXT,base+0x35DC50),(OTHER_CONTEXT,base+0x35DC50)):
        write(a,v)
    count = 2 if profile=='null_then_registry' else 1 if profile in ('registry','null_registry_fallback') else 0
    write(CONTROL+8,count)
    for i in range(count):
        node, pair = G+0x9600+i*0x40, G+0x9700+i*0x20
        target = base+0x2830C4 if profile=='registry' or i==1 else 0
        for a,v in ((node,1 if not i else 0),(node+8,SENTINEL if not i else node-0x40),
            (node+16,0),(node+24,node+0x40 if i+1<count else 0),(node+32,pair),
            (pair,target),(pair+8,OTHER_CONTEXT)):
            write(a,v)
    if count:
        write(SENTINEL+8,G+0x9600); write(SENTINEL+16,G+0x9600)
        write(SENTINEL+24,G+0x9600+(count-1)*0x40)
    # Seed the eventual wrapper argument region before any original instruction.
    # This is guest input memory, not an on-the-fly mutation or code patch.
    _write_span(pages,G+0xD400,bytes([control['padding_byte']])*0x400)


def validate(data):
    assert data['schema']=='vm9-native-171-vm-handoff-20261118-v1'
    assert data['provenance']==dict(Metasec_sha256=inputs.SHA256,Bionic_sha256=inputs.LIBC_SHA256,
        upstream_input_evidence=inputs.EVIDENCE.name,
        independent_constructor_evidence='vm9_outer_graph_object_provenance_20261028.json')
    assert data['boundary']==BOUNDARY and data['claims']==CLAIMS
    assert data['providers']==inputs.PROVIDERS and data['limits']==LIMITS
    assert data['synthetic_memory_only'] is True and data['Android_execution'] is False
    assert data['real_requests_or_connection_details_published'] is False
    assert data['static_instruction_bindings']==[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED]
    assert [(int(r['start'],16),int(r['end_exclusive'],16)) for r in data['code_ranges']]==RANGES
    assert all(inputs.is_digest(r['sha256']) for r in data['code_ranges'])
    assert len(data['case_results'])==len(controls())
    for row,control in zip(data['case_results'],controls()):
        assert row['control']==control
        assert row['call_site']==('0x27e478' if is_registry(control) else '0x27e6a8')
        context=selected_context(control)
        assert row['callback_context_guest_offset']==(hex(context-G) if context else None)
        assert row['native_mode']=='0x171' and row['callback_url_reference_count']==3 and row['callback_tree_reference_count']==3
        assert row['mode_padding_hex']==bytes([control['padding_byte']]*4).hex()
        assert row['shared_readers_at_VM_entry']==(8 if control['profile']=='readers7' else 1)
        assert row['mutex_events']==20 and row['instructions_executed']>1000
        for key in ('wrapper_packed_and_saved_spans_match','wrapper_VM_call_registers_match',
                    'mode_padding_preserved','semantic_inputs_preserved','executed_code_unchanged'):
            assert row[key] is True
        assert row['VM_instructions_executed']==0 and row['unexpected_external_or_legacy_calls']==0
        for key in ('trace_sha256','guest_heap_sha256','allocation_ledger_sha256','mutex_ledger_sha256'):
            assert inputs.is_digest(row[key])


def verify_elf(data,path):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    upstream=json.loads(inputs.EVIDENCE.read_text(encoding='utf-8')); inputs.validate(upstream)
    prior=inputs.verify_elf(upstream,path)
    elf,_,read=inputs.load_elf(path); decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for a,m,s in EXPECTED:
        ins,=decoder.disasm(read(a,4),a)
        assert (ins.mnemonic,ins.op_str)==(m,s),hex(a)
    for row in data['code_ranges']:
        a,b=int(row['start'],16),int(row['end_exclusive'],16)
        assert hashlib.sha256(read(a,b-a)).hexdigest()==row['sha256']
    refs={r['r_offset']:r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()
          if r['r_info_type']==1027 and r['r_offset']==0x35DCB8}
    assert refs=={0x35DCB8:0x28509C}
    return dict(upstream=prior,additional_instructions=len(EXPECTED),additional_code_ranges=len(RANGES),
                handler_vtable_relative_relocations=1)


def replay(path,libc,*,case_controls=None,on_case=None,_native_runner=None):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    from unicorn import arm64_const as arm
    import verify_vm9_signer_objects as oracle
    from verify_vm9_strings import Effects
    from vm9_allocator import _read_span
    from vm9_request_caller import prepare_request_caller
    _,loads,read_main=inputs.load_elf(path); libc_elf,exports=inputs.libc_image(libc)
    libc_loads=[s for s in libc_elf.iter_segments() if s['p_type']=='PT_LOAD']
    libc_bytes=[(s['p_vaddr'],s.data()) for s in libc_loads]
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM); decoded=set()
    selected=controls() if case_controls is None else case_controls
    images={base:oracle.image_pages(path,base) for base in {c['base'] for c in selected}}
    rows=[]
    for control in selected:
        base=control['base']; pages=inputs.fixture_pages(images[base],control); prepare_graph(pages,control)
        effects=Effects(blocks=()); trace=[]; external=Counter(); visited=set(); child_inputs=[]
        callbacks=[]; wrapper_matches=[]; expected_frame=[]; inspected=[]
        spans=[(base+s['p_vaddr'],base+s['p_vaddr']+s['p_memsz']) for s in loads if s['p_flags']&1]
        spans += [(inputs.LIBC_BASE+s['p_vaddr'],inputs.LIBC_BASE+s['p_vaddr']+s['p_memsz']) for s in libc_loads if s['p_flags']&1]
        def redirect(name):
            def call(c): c.reg_write(arm.UC_ARM64_REG_PC,exports[name])
            return call
        imports={0x347FA0:lambda c:effects.native(c,'free',pointer=c.reg_read(arm.UC_ARM64_REG_X0)),
            0x348320:lambda c:effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0)),
            0x347FE0:redirect('memcmp'),0x3480B0:redirect('strcmp')}
        def observe(c,a):
            off=a-base; domain='metasec'
            if inputs.LIBC_BASE<=a<inputs.LIBC_BASE+0x200000:
                domain='libc'; off=a-inputs.LIBC_BASE
                start,payload=next((s,b) for s,b in libc_bytes if s<=off and off+4<=s+len(b))
                original=payload[off-start:off-start+4]
            else:
                original=read_main(off,4)
                assert off not in (0x26EDC4,0x26E70C,0x15F094,0x264158,0x168324),hex(off)
                if off in inputs.IMPORTS: external[inputs.IMPORTS[off][0]]+=1
                elif 0x347E00<=off<0x348800: raise AssertionError('unexpected import '+hex(off))
            site=(domain,off); trace.append([domain,off])
            if site not in decoded:
                ins,=decoder.disasm(original,off)
                assert ins.mnemonic not in ('svc','hvc','smc','brk','hlt'),site
                decoded.add(site)
            if site not in visited:
                assert bytes(c.mem_read(a,4))==original,site;visited.add(site)
            def reg(n): return c.reg_read(getattr(arm,'UC_ARM64_REG_'+n.upper()))
            def word(a,n=8): return int.from_bytes(c.mem_read(a,n),'little')
            if a==base+0x27DD04:
                assert reg('x0')==CHILD and reg('x3')==0x171
                child_inputs.append((bytes(c.mem_read(reg('x1'),16)),bytes(c.mem_read(reg('x2'),16))))
            if a in (base+0x27E478,base+0x27E6A8):
                inspected.append(hex(a-base))
                assert a-base==(0x27E478 if is_registry(control) else 0x27E6A8)
                assert reg('x9')==base+0x2830C4
            if a==base+0x2830C4:
                assert len(callbacks)==0 and len(child_inputs)==1 and len(inspected)==1
                assert reg('x2')==0x171 and reg('x3')==selected_context(control)
                url,tree=reg('x0'),reg('x1')
                assert (bytes(c.mem_read(url,16)),bytes(c.mem_read(tree,16)))==child_inputs[0]
                assert word(word(url+8),4)==word(word(tree+8),4)==3
                def string(obj):
                    assert word(obj)==base+0x34F5F8
                    length=word(obj+12,4);assert length<0x1000
                    return bytes(c.mem_read(word(obj+16),length))
                assert string(word(url))==bytes.fromhex(control['first_hex']).split(b'\0',1)[0]
                container=word(tree);assert word(container)==base+0x35B7C0
                controller=word(container+32);sentinel=word(controller);pairs=[];seen=set()
                def visit(node):
                    if not node:return
                    assert node not in seen and len(seen)<128;seen.add(node)
                    visit(word(node+16));pair=word(node+32)
                    pairs.append([string(word(pair)).hex(),string(word(pair+8)).hex()])
                    visit(word(node+24))
                visit(word(sentinel+8))
                assert len(pairs)==word(controller+8) and pairs==inputs.expected_pairs(control)
                callbacks.append(dict(url_count=3,tree_count=3,context=reg('x3')))
                before={**images[base],**{page:bytearray(c.mem_read(page<<12,4096)) for page in range(G>>12,(G+0x10000)>>12)}}
                frame=prepare_request_caller(before,entry_stack_address=reg('sp'),return_address=reg('x30'),
                    thread_pointer=TLS,image_base=base,argument_x0=url,argument_x1=tree,
                    argument_x2=reg('x2'),argument_x3=reg('x3'),output_x8=reg('x8'),
                    saved_frame_pointer=reg('x29'),saved_x28=reg('x28'),saved_x19=reg('x19'))
                regions=[(frame.packed_arguments_address,0x40),(reg('sp')-0x28,0x28)]
                expected_frame.append((frame,[(a,_read_span(before,a,n)) for a,n in regions]))
                assert bytes(c.mem_read(frame.native_stack_address+0x24,4))==bytes([control['padding_byte']])*4
            if a==base+0x283130:
                assert len(expected_frame)==1
                frame,regions=expected_frame[0]
                assert tuple(reg('x'+str(i)) for i in range(5))==frame.vm_call_registers
                assert all(bytes(c.mem_read(a,len(raw)))==raw for a,raw in regions)
                packed=frame.packed_arguments_address
                assert word(packed+0x18,4)==0x171 and word(packed+0x20)==selected_context(control)
                assert bytes(c.mem_read(packed+0x1C,4))==bytes([control['padding_byte']])*4
                wrapper_matches.append(True)
        observed={(MUTEX+0x90,8):None}
        def writes(c,a,n): assert not any(a<end and start<a+n for start,end in spans),hex(a)
        runner=oracle.native if _native_runner is None else _native_runner
        _,heap,default_alloc,locks=runner(path,base,0x27ED14,[G+0x800,0,0],pages,libc=libc,
            real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
            real_jni_acquisition=True,real_jni_dispatch=True,stop_offset=0x168324,
            extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TLS},
            malloc_handler=lambda c,n:effects.native(c,'malloc',n),host_imports=imports,
            instruction_observer=observe,memory_write_observer=writes,observed_memory=observed,instruction_limit=100000)
        assert not default_alloc and len(wrapper_matches)==len(callbacks)==1
        # The read scope remains held because the request callback has not returned.
        readers=int.from_bytes(observed[MUTEX+0x90,8][:4],'little')
        assert observed[MUTEX+0x90,8][4]==1
        normalize=lambda v:v-G if G<=v<G+0x10000 else v
        alloc=[[e[0],*[normalize(v) for v in e[1:]]] for e in effects.calls]
        row=dict(control=control,call_site=inspected[0],native_mode='0x171',
            callback_context_guest_offset=hex(selected_context(control)-G) if selected_context(control) else None,
            callback_url_reference_count=3,callback_tree_reference_count=3,
            mode_padding_hex=bytes([control['padding_byte']]*4).hex(),
            shared_readers_at_VM_entry=readers,mutex_events=len(locks),
            instructions_executed=len(trace)-sum(external.values()),
            trace_sha256=inputs.digest_json(trace),guest_heap_sha256=hashlib.sha256(heap).hexdigest(),
            allocation_ledger_sha256=inputs.digest_json(alloc),
            mutex_ledger_sha256=inputs.digest_json([[n,normalize(a)] for n,a in locks]),
            wrapper_packed_and_saved_spans_match=True,wrapper_VM_call_registers_match=True,
            mode_padding_preserved=True,semantic_inputs_preserved=True,executed_code_unchanged=True,
            VM_instructions_executed=0,unexpected_external_or_legacy_calls=0)
        rows.append(row)
        if on_case is not None: on_case(row)
    return rows


def build(path,libc,*,on_case=None):
    _,_,read=inputs.load_elf(path); inputs.libc_image(libc)
    data=dict(schema='vm9-native-171-vm-handoff-20261118-v1',
        provenance=dict(Metasec_sha256=inputs.SHA256,Bionic_sha256=inputs.LIBC_SHA256,
            upstream_input_evidence=inputs.EVIDENCE.name,
            independent_constructor_evidence='vm9_outer_graph_object_provenance_20261028.json'),
        boundary=BOUNDARY,claims=CLAIMS,providers=inputs.PROVIDERS,limits=LIMITS,
        synthetic_memory_only=True,Android_execution=False,real_requests_or_connection_details_published=False,
        static_instruction_bindings=[dict(offset=hex(a),mnemonic=m,operands=s) for a,m,s in EXPECTED],
        code_ranges=[dict(start=hex(a),end_exclusive=hex(b),sha256=hashlib.sha256(read(a,b-a)).hexdigest()) for a,b in RANGES],
        case_results=[])
    verify_elf(data,path);data['case_results']=replay(path,libc,on_case=on_case);validate(data)
    return data


def negatives(data):
    bad_records=[]
    for key,value in CLAIMS.items():
        bad=deepcopy(data);bad['claims'][key]=not value;bad_records.append(bad)
    for control_index in range(len(controls())):
        for key,value in (('native_mode','0x138'),('mode_padding_preserved',False),('callback_tree_reference_count',2)):
            bad=deepcopy(data);bad['case_results'][control_index][key]=value;bad_records.append(bad)
    for key,value in (('callback_x3_source','VM direct x3'),('direct_VM_x3','selected callback pair +0x08')):
        bad=deepcopy(data);bad['boundary'][key]=value;bad_records.append(bad)
    for bad in bad_records:
        try:validate(bad)
        except AssertionError:pass
        else:raise AssertionError('damaged handoff evidence accepted')
    return len(bad_records)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    parser.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if args.replay and (not args.elf or not args.libc):parser.error('--replay requires --elf and --libc')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data)
    result=dict(retained_synthetic_cases=len(controls()),damaged_evidence_rejected=negatives(data),
                request_VM_executed=False,actual_business_callback_execution_verified=False)
    if args.elf:result['Metasec_bindings']=verify_elf(data,args.elf)
    if args.libc:inputs.libc_image(args.libc);result['matching_Bionic_digest_verified']=True
    if args.replay:
        assert replay(args.elf,args.libc)==data['case_results'],'frozen replay differs'
        result['original_code_cases_replayed']=len(controls())
    print(json.dumps(result))


if __name__=='__main__':main()
