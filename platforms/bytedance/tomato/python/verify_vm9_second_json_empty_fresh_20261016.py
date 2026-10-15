"""Fresh +28883c/+261404 empty JSON object reference and NULL-source path.

This bounded stage accepts an empty object prefix with native whitespace/BOM
rules. Other JSON values are refused. The native parser executes in controls.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import vm9_request_287474_vm as second
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;SP=dependency.SP;TP=dependency.TP
PROFILES=('empty_object','NULL_source','leading_space','inner_space','control_space',
    'BOM_object','ignored_trailing','NUL_terminates','warm','cross_source','cross_output','cross_packed')
GUARDS=('wrong_target','unaligned_stack','unmapped_source','unmapped_output','unterminated_source',
    'nonempty_object','array','scalar','bad_object','guard_wait','NULL_new','provider_failure',
    'packed_stack_alias','output_stack_alias','source_stack_alias','custom_hooks')


def fresh(library,image,label):
    p=dependency.fresh(library,image,warm=label=='warm')
    packed=G+0x6FF8 if label=='cross_packed' else G+0x2400
    out=G+0x1FF8 if label=='cross_output' else G+0x1000
    source=G+0x2FFF if label=='cross_source' else G+0x2800
    payload={'leading_space':b' \t\r\n{}','inner_space':b'{ \t\r\n}',
        'control_space':b'\x01\x1f{\x02\x20}', 'BOM_object':b'\xef\xbb\xbf{}',
        'ignored_trailing':b'{}trailing', 'NUL_terminates':b'{}\x00ignored'}.get(label,b'{}')
    if label=='NULL_source':source=0
    if source:_write_span(p,source,payload+b'\x00')
    _write_span(p,packed,(image+0x261404).to_bytes(8,'little')+out.to_bytes(8,'little')+
        source.to_bytes(8,'little')+b'\x5A'*16)
    _write_span(p,image+0x381AA0,(image+0x347FD0).to_bytes(8,'little')+(image+0x347FA0).to_bytes(8,'little'))
    _write_span(p,image+0x3DE420,b'\x72'*16)
    return p,packed,out


def original(library,libc,image,p,packed):
    effects=dependency.Services();scopes=[];steps=[0];seen=set()
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    with libc.open('rb') as stream:
        elf=oracle.ELFFile(stream)
        strncmp=next(0x51000000+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name=='strncmp' and s['st_shndx']!='SHN_UNDEF')
    def compare_prefix(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,strncmp)
    def observe(cpu,a):
        steps[0]+=1;off=a-image
        if off in (0x28883C,0x261404,0x17CDB4):seen.add(off)
        if off in (0x347F00,0x347F10):effects.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:effects.diagnostic('gettid',137)
        elif off==0x26C9D0:
            a=cpu.reg_read(arm.UC_ARM64_REG_X0);scopes.append((a,bytes(cpu.mem_read(a,24))))
    _,memory,allocations,ledger=oracle.native(library,image,0x28883C,[packed],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        malloc_handler=effects.native_malloc,host_imports={0x347FA0:effects.native_free,0x348400:compare_prefix},instruction_observer=observe,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_limit=100000)
    assert seen=={0x28883C,0x261404,0x17CDB4} and not allocations
    return memory,watch,scopes,effects,steps[0]


def red(library,libc):
    assert not hasattr(second,'RequestVm287474JsonPrefix');rows=[]
    for image in BASES:
        p,packed,out=fresh(library,image,'empty_object');memory,_,scopes,effects,steps=original(library,libc,image,p,packed)
        assert int.from_bytes(memory[out-G:out-G+8],'little') and scopes and effects.freed
        rows.append(dict(image_base=hex(image),previous_second_json_dispatch_missing=True,
            original_wrapper_parser_and_scoped_reference_returned=True,steps=steps,
            native_empty_JSON_object_and_reference_count_observed=True,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,packed,out=fresh(library,image,label);memory,watch,expected_scopes,expected,steps=original(library,libc,image,p,packed)
    actual=dependency.Services();actual_scopes=[]
    leave=dependency.diagnostics.leave_diagnostic_scope
    def record_scope(tx,**kw):
        address=kw['object_address'];actual_scopes.append((address,_read_span(tx,address,24)))
        return leave(tx,**kw)
    try:
        dependency.diagnostics.leave_diagnostic_scope=record_scope
        result=second.apply_request_287474_json_callback(p,argument_block_address=packed,
            entry_stack_address=SP,image_base=image,thread_pointer=TP,thread_id=137,
            allocate=actual.malloc,free=actual.free,diagnostic_observer=actual.diagnostic)
    finally:dependency.diagnostics.leave_diagnostic_scope=leave
    assert actual_scopes==expected_scopes,(label,'scope before leave',actual_scopes,expected_scopes)
    ours=_read_span(p,G,0xA000)
    assert ours==memory,(label,'guest',next((hex(i) for i,(a,b) in enumerate(zip(ours,memory)) if a!=b),None))
    for (a,n),b in watch.items():assert _read_span(p,a,n)==b,(label,hex(a),_read_span(p,a,n).hex(),b.hex())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.freed==expected.freed,(label,'effects',actual.events,expected.events)
    assert actual.effects.blocks==expected.effects.blocks and result==int.from_bytes(_read_span(p,out,8),'little')
    print('PASS second JSON empty',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_wrapper_parser_and_scoped_reference_returned=True,guest_image_packed_and_defined_scope_bytes_equal=True,
        ordered_allocator_free_diagnostic_and_prefree_bytes_equal=True,actual_matching_libc_recursive_mutexes=True,
        no_packed_result_store=True,native_snapshot_input=False,native_physical_X0_compared=False)


def guards(library):
    rows=[]
    for label in GUARDS:
        image=BASES[0];p,packed,out=fresh(library,image,'empty_object');service=dependency.Services()
        kw=dict(argument_block_address=packed,entry_stack_address=SP,image_base=image,thread_pointer=TP,thread_id=137,
            allocate=service.malloc,free=service.free,diagnostic_observer=service.diagnostic)
        if label=='wrong_target':_write_span(p,packed,(image+0x261490).to_bytes(8,'little'))
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='unmapped_source':_write_span(p,packed+16,(0x66000000).to_bytes(8,'little'))
        elif label=='unmapped_output':_write_span(p,packed+8,(0x66000000).to_bytes(8,'little'))
        elif label=='unterminated_source':_write_span(p,G+0x2800,b' '*4096)
        elif label in ('nonempty_object','array','scalar','bad_object'):
            _write_span(p,G+0x2800,{'nonempty_object':b'{"a":1}\0','array':b'[]\0','scalar':b'1\0','bad_object':b'{x}\0'}[label])
        elif label=='guard_wait':_write_span(p,image+dependency.diagnostics.GUARD+1,b'\x02')
        elif label=='NULL_new':kw['allocate']=lambda p,n:0
        elif label=='provider_failure':
            def failure(tx,n):_write_span(tx,G+0x5000,b'effect');raise RuntimeError('provider failed')
            kw['allocate']=failure
        elif label=='packed_stack_alias':
            _write_span(p,SP-0x20,_read_span(p,packed,40));kw['argument_block_address']=SP-0x20
        elif label=='output_stack_alias':_write_span(p,packed+8,(SP-0x20).to_bytes(8,'little'))
        elif label=='source_stack_alias':_write_span(p,packed+16,(SP-0x20).to_bytes(8,'little'))
        elif label=='custom_hooks':_write_span(p,image+0x381AA8,(image+0x32A264).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_json_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError('JSON guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native','guards'),default='native');ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_JSON_parser_verified=False,
        complete_second_vm_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,a.libc,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
