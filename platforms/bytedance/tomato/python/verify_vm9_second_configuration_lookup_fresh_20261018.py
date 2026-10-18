"""Fresh configuration lookup and nested scoped reference comparisons.

Inputs are independently constructed; original results never initialize the
model. Allocation services are synthetic. Physical spills and scope padding
are excluded, while scope addresses, owned fields and ordered effects agree.
"""
from pathlib import Path
import argparse, hashlib, json, os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as dependency
from verify_vm9_configuration_init import string_object
from vm9_allocator import _read_span, _write_span, RefillUnsupported
import vm9_diagnostics as diagnostics
import vm9_objects as objects
import vm9_reference_scopes as references
import vm9_cipher_callback as cipher
import vm9_stream_cipher as stream
import vm9_request_287474_vm as second

G=oracle.GUEST; SP=dependency.SP; TP=dependency.TP
BASES=(0x122C0000,0x775C205000)
PRIMITIVES=('decoded','decoded_invalid','cipher_empty','cipher_invalid_key',
    'stream','stream_empty','sha1_empty','sha1_short','sha1_multiblock')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','output_NULL','output_unmapped',
    'receiver_NULL','key_NULL','output_receiver_alias','output_key_alias','output_packed_alias',
    'packed_spill','output_spill','receiver_spill','key_spill','unaligned_stack','stack_wrap',
    'missing_allocate','missing_reallocate','missing_free','missing_singleton',
    'invalid_entry_bound','invalid_byte_bound','unknown_iterator','publication_cycle',
    'publication_bound','publication_key_bound','allocation_spill','allocation_alias',
    'provider_failure','late_free_failure','parser_abort','empty_source_abort','sha1_hex_unrecovered')

def w(p,a,v,n=8): _write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def u(p,a,n=8): return int.from_bytes(_read_span(p,a,n),'little')

def fixture(library,image,label):
    p=dependency.fresh(library,image)
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    out=G+(0x2FF8 if label=='cross_output' else 0x1100)
    config,key,source,count=G+0x1800,G+0x1900,G+0x1A00,G+0x1B00
    _write_span(p,config,bytes(88));w(p,config+8,source);w(p,config+16,count);w(p,count,3,4)
    payload=b'' if label=='empty' else b'====' if label=='decoded_empty' else b'!'
    string_object(p,image,source,payload,payload=G+0x2100)
    string_object(p,image,key,b'selected',payload=G+0x2200)
    if label.startswith('publication'):
        container,controller,sentinel,node,entry=G+0x2500,G+0x2600,G+0x2700,G+0x2800,G+0x2900
        _write_span(p,container,bytes(48));w(p,container+40,controller);w(p,controller,sentinel)
        w(p,config+72,container);w(p,sentinel,sentinel)
        if label!='publication_empty':
            w(p,sentinel,node);w(p,node,sentinel);w(p,node+8,sentinel);w(p,node+16,entry)
            string_object(p,image,entry,b'first',payload=G+0x2A00)
            if label=='publication_two':
                w(p,node,G+0x2B00);w(p,G+0x2B00,sentinel);w(p,G+0x2B08,node);w(p,G+0x2B10,entry)
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x263174,out,config,key))+b'\x5A'*8)
    return p,block,out,config,key

def invoke(p,s,image,block,vm,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,
        thread_pointer=TP,vm_module=vm,allocate=s.malloc,reallocate=s.effects.realloc,
        free=s.free,get_singleton=lambda *args: (_ for _ in ()).throw(AssertionError('unexpected singleton')),
        thread_id=137,diagnostic_observer=s.diagnostic)
    kw.update(changes or {})
    return second.apply_request_287474_configuration_lookup_callback(p,**kw)

def primitive(library,libc,image,label):
    p=dependency.fresh(library,image);out=G+0x1000;data=G+0x1800;key=G+0x1900
    iv,mode=G+0x1A00,G+0x1B00
    payload=b'' if label.endswith('empty') else b'x'*129 if label=='sha1_multiblock' else b'abc'
    if label.startswith('decoded'):payload=b'!' if label.endswith('invalid') else b'YWJj'
    string_object(p,image,data,payload,payload=G+0x2100)
    string_object(p,image,key,b'key',payload=G+0x2200)
    string_object(p,image,iv,bytes(16),payload=G+0x2300);w(p,mode,0,4)
    expected=dependency.Services();actual=dependency.Services();native_scopes=[];model_scopes=[]
    if label.startswith('decoded'):entry,args=0x258E7C,[data]
    elif label.startswith('cipher'):entry,args=0x259DBC,[data,key,iv,mode]
    elif label.startswith('stream'):entry,args=0x2592B8,[data,key]
    else:entry,args=0x258780,[data,0]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[G,SP-G-0x8000]=None
    def observe(cpu,a):
        off=a-image
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
        if off==0x26C9D0:
            address=cpu.reg_read(arm.UC_ARM64_REG_X0);raw=bytes(cpu.mem_read(address,24))
            native_scopes.append((address,raw[:12]+raw[16:]))
    oracle.native(library,image,entry,args,p,libc=libc,real_diagnostics=True,real_singletons=True,
        real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_X8:out},
        malloc_handler=expected.native_malloc,host_imports={0x347FA0:expected.native_free},
        observed_memory=watch,instruction_observer=observe,instruction_limit=1000000)
    services=dict(thread_pointer=TP,thread_id=137,diagnostic_observer=actual.diagnostic)
    common=dict(entry_stack_address=SP,image_base=image,allocate=actual.malloc,free=actual.free)
    leave=diagnostics.leave_diagnostic_scope
    def record(q,**kw):
        address=kw['object_address'];raw=_read_span(q,address,24)
        model_scopes.append((address,raw[:12]+raw[16:]));return leave(q,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record
        if label.startswith('decoded'):
            objects.construct_decoded_configuration_reference(p,object_address=out,source_object_address=data,
                diagnostic_services=services,**common)
        elif label.startswith('cipher'):
            cipher.decrypt_configuration_reference(p,output_reference_address=out,data_object_address=data,
                key_object_address=key,iv_object_address=iv,mode_address=mode,
                diagnostic_services=services,get_singleton=lambda *args:0,**common)
        elif label.startswith('stream'):
            stream.transform_configuration_reference(p,output_reference_address=out,data_object_address=data,
                key_object_address=key,diagnostic_services=services,**common)
        else:
            references.construct_scoped_digest_reference(p,output_reference_address=out,source_object_address=data,
                algorithm='sha1',flag=0,reallocate=actual.effects.realloc,**services,**common)
    finally:diagnostics.leave_diagnostic_scope=leave
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    assert actual.events==expected.events and actual.freed==expected.freed,label
    assert actual.effects.blocks==expected.effects.blocks and model_scopes==native_scopes,(label,'scope fields')
    print('PASS nested reference',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,original_returned=True,declared_nonstack_memory_equal=True,
        ordered_effects_and_prefree_bytes_equal=True,scope_addresses_and_owned_fields_equal=True,
        scope_padding_compared=False,native_snapshot_input=False)

def guards(library,vm):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,out,config,key=fixture(library,image,'publication_first');s=dependency.Services();changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label in ('output_NULL','output_unmapped'):w(p,block+8,0 if label.endswith('NULL') else 0x66000000)
        elif label=='receiver_NULL':w(p,block+16,0)
        elif label=='key_NULL':w(p,block+24,0)
        elif label=='output_receiver_alias':w(p,block+8,config)
        elif label=='output_key_alias':w(p,block+8,key)
        elif label=='output_packed_alias':w(p,block+8,block)
        elif label=='packed_spill':_write_span(p,SP-32,_read_span(p,block,32));block=SP-32
        elif label in ('output_spill','receiver_spill','key_spill'):
            w(p,block+{'output_spill':8,'receiver_spill':16,'key_spill':24}[label],SP-64)
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='stack_wrap':changes['entry_stack_address']=1<<64
        elif label.startswith('missing_'):changes[{'missing_allocate':'allocate','missing_reallocate':'reallocate','missing_free':'free','missing_singleton':'get_singleton'}[label]]=None
        elif label=='invalid_entry_bound':changes['max_entries']=True
        elif label=='invalid_byte_bound':changes['max_bytes']=0x100001
        elif label=='unknown_iterator':w(p,image+0x381AB8+8,image+1)
        elif label=='publication_cycle':w(p,G+0x2800,G+0x2800)
        elif label=='publication_bound':
            w(p,G+0x2800,G+0x2B00);w(p,G+0x2B00,G+0x2700);changes['max_entries']=1
        elif label=='publication_key_bound':changes['max_bytes']=2
        elif label=='allocation_spill':changes['allocate']=lambda tx,n:SP-64
        elif label=='allocation_alias':changes['allocate']=lambda tx,n:config
        elif label=='provider_failure':
            def fail(tx,n):s.malloc(tx,n);raise RefillUnsupported('provider failed after allocation')
            changes['allocate']=fail
        elif label=='late_free_failure':
            def fail(tx,a):s.free(tx,a);raise RefillUnsupported('provider failed after free')
            changes['free']=fail
        elif label=='empty_source_abort':w(p,G+0x1A00+12,0,4)
        before={k:bytes(v) for k,v in p.items()}
        try:
            if label=='sha1_hex_unrecovered':
                references.construct_scoped_digest_reference(p,output_reference_address=out,
                    source_object_address=G+0x1A00,entry_stack_address=SP,image_base=image,
                    thread_pointer=TP,thread_id=137,allocate=s.malloc,reallocate=s.effects.realloc,
                    free=s.free,algorithm='sha1',flag=1)
            else:invoke(p,s,image,block,vm,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    rows=[]
    for image in BASES:
        rows.extend(primitive(args.library,args.libc,image,label) for label in PRIMITIVES)
    negative=guards(args.library,vm_full)
    result=dict(component='Second configuration lookup and nested scoped references',
        native_Python_controls=len(rows),rollback_guards=len(negative),cases=rows,negative_cases=negative,
        library_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=dependency.LIBC_SHA256,
        native_snapshot_input=False,synthetic_allocation_services=True,complete_signer_verified=False,
        physical_ABI_verified=False,external_effect_rollback_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS configuration lookup',len(rows),'controls',len(negative),'guards',flush=True)

if __name__=='__main__':main()
