"""Fresh compact JSON printing versus original allocation, writes and cleanup."""
from pathlib import Path
import argparse,hashlib,json,struct
from functools import lru_cache
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_outer_signer_native as native_outer
from verify_vm9_shared_reference import fixture as format_fixture,TLS
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_configuration_init as configuration
G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
PROFILES=('NULL','false','true','null','invalid','empty_array','empty_object','empty_string','NULL_string',
    'binary','NUL','escapes','growth','object','nested','raw','number','negative_zero','precise','infinity',
    'initial_failure','final_failure','growth_failure','NULL_raw')
GUARDS=('unaligned_stack','missing_allocator','missing_free','custom_malloc','custom_free','custom_realloc',
    'unmapped_node','unmapped_string','unterminated_string','cyclic_children','depth_bound','node_bound',
    'byte_bound','node_spill','source_spill','invalid_allocation','allocation_spill','provider_failure','free_failure','changed_source')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def fixture(library,libc,image,label):
    p=format_fixture(library,image,libc);root=G+0x2000
    def node(a,kind,text=None,bits=0):
        _write_span(p,a,bytes(64));w(p,a+24,kind,4);w(p,a+48,bits)
        if text is not None:w(p,a+32,G+0x3000);_write_span(p,G+0x3000,text+b'\0')
    kind={'false':1,'true':2,'null':4,'invalid':0,'empty_array':32,'empty_object':64,
        'object':64,'nested':32,'raw':128,'NULL_raw':128,'number':8,'negative_zero':8,'precise':8,'infinity':8}.get(label,16)
    text={'empty_string':b'','binary':b'\x80\xffx','NUL':b'a\0tail','escapes':bytes(range(1,32))+b'"\\/',
        'growth':b'x'*600,'growth_failure':b'x'*600,'raw':b'{"raw":1}'}.get(label,b'value')
    bits={'number':0x41B914D5CC000000,'negative_zero':1<<63,'precise':struct.unpack('<Q',struct.pack('<d',1.2345678901234567))[0],
        'infinity':0x7FF0000000000000}.get(label,0)
    node(root,kind,text if kind in (16,128) and label not in ('NULL_string','NULL_raw') else None,bits)
    if label in ('object','nested'):
        first,second=G+0x2100,G+0x2200;node(first,2);node(second,4)
        w(p,root+16,first);w(p,first,second)
        for a,key in ((first,b'a'),(second,b'key"')):
            k=a+0x500;w(p,a+56,k);_write_span(p,k,key+b'\0')
        if label=='nested':w(p,first+24,64,4);w(p,first+16,G+0x2300);node(G+0x2300,1);w(p,G+0x2338,G+0x2700);_write_span(p,G+0x2700,b'n\0')
    w(p,image+0x381AA0,image+0x347FD0);w(p,image+0x381AA8,image+0x347FA0);w(p,image+0x381AB0,0)
    return p,0 if label=='NULL' else root
def service(label):return Services(failures=(0,) if label=='initial_failure' else (1,) if label in ('final_failure','growth_failure') else ())
@lru_cache(maxsize=1)
def native_imports(library,libc):
    imports={}
    def redirect(a):
        def go(c):c.reg_write(arm.UC_ARM64_REG_PC,a)
        return go
    native_outer.bind_native_imports(library,libc,redirect,imports)
    return imports
def original(library,libc,image,p,root,s):
    imports=dict(native_imports(library,libc));imports[0x347FA0]=s.native_free
    steps=[0];seen=set();wake=[];scratch=[0x61000000]
    def observe(c,a):
        steps[0]+=1
        if a-image in (0x249AF0,0x2499B0,0x249BB8,0x24AC94):seen.add(a-image)
    def syscall(c,n):
        if n==222:
            size=c.reg_read(arm.UC_ARM64_REG_X1);address=scratch[0]
            c.mem_map(address,(size+4095)&~4095);scratch[0]+=(size+4095)&~4095
            return address
        if n in (215,226):return 0
        assert n==98,(n,hex(c.reg_read(arm.UC_ARM64_REG_PC)),[hex(c.reg_read(r)) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)])
        args=[c.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)]
        assert args[1]==129;wake.append(args);return 0
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,0xA000):None,(TLS,0xB00):None,(0x510DE930,16):None,(0x510E0200,0x800):None})
    result,_,allocations,ledger=oracle.native(library,image,0x249AF0,[root],p,libc=libc,
        malloc_handler=s.native_malloc,host_imports=imports,syscall_handler=syscall,
        instruction_observer=observe,observed_memory=watch,instruction_limit=600000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TLS})
    assert {0x249AF0,0x2499B0}<=seen and not allocations and not ledger
    return result,watch,wake,steps[0]
def compare(library,libc,image,label):
    p,root=fixture(library,libc,image,label);expected=service(label);actual=service(label)
    result,watch,expected_wake,steps=original(library,libc,image,p,root,expected)
    import vm9_json_print as model
    wake=[]
    def prepare(tx):configuration.prepare_bionic_format_locale(tx,once_address=0x510DE938,key_address=0x510DE930,
        generation_table=0x510E0200,thread_pointer=TLS,wake=lambda tx,*a:wake.append(list(a)) or 0)
    ours=model.print_json_unformatted(p,node_address=root,entry_stack_address=SP,image_base=image,
        allocate=actual.malloc,free=actual.free,prepare_format=prepare)
    assert ours==result,(label,'pointer',hex(ours),hex(result))
    for (a,n),raw in watch.items():
        value=_read_span(p,a,n)
        assert value==raw,(label,hex(a),next((i for i,(x,y) in enumerate(zip(value,raw)) if x!=y),None))
    assert actual.events==expected.events and actual.freed==expected.freed and actual.effects.blocks==expected.effects.blocks,(label,'effects',actual.events,expected.events)
    assert wake==expected_wake,(label,'locale',wake,expected_wake)
    print('PASS JSON print',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_compact_printer_returned=True,
        all_declared_guest_image_TLS_locale_bytes_equal=True,ordered_allocation_free_and_prefree_bytes_equal=True,
        locale_wake_effects_equal=True,output_pointer_equal=True,native_snapshot_input=False,
        synthetic_allocation_services=True,complete_physical_ABI_verified=False)
def guards(library,libc):
    import vm9_json_print as model
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,root=fixture(library,libc,image,'object');s=service('object')
        kw=dict(node_address=root,entry_stack_address=SP,image_base=image,allocate=s.malloc,free=s.free)
        if label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_free':kw['free']=None
        elif label.startswith('custom_'):w(p,image+{'custom_malloc':0x381AA0,'custom_free':0x381AA8,'custom_realloc':0x381AB0}[label],1)
        elif label=='unmapped_node':kw['node_address']=0x66000000
        elif label in ('unmapped_string','unterminated_string','source_spill'):
            w(p,root+24,16,4);address=0x66000000 if label=='unmapped_string' else G+0x9000 if label=='unterminated_string' else SP-16
            w(p,root+32,address)
            if label=='unterminated_string':_write_span(p,address,b'x'*4096);kw['max_bytes']=4096
        elif label=='cyclic_children':w(p,G+0x2100,G+0x2100)
        elif label=='depth_bound':kw['max_depth']=1;w(p,G+0x2100+24,32,4);w(p,G+0x2100+16,G+0x2200)
        elif label=='node_bound':kw['max_nodes']=1
        elif label=='byte_bound':kw['max_bytes']=4
        elif label=='node_spill':kw['node_address']=SP-64
        elif label=='invalid_allocation':kw['allocate']=lambda tx,n:True
        elif label=='allocation_spill':kw['allocate']=lambda tx,n:SP-64
        elif label=='changed_source':
            w(p,root+24,16,4);w(p,root+32,G+0x3000);_write_span(p,G+0x3000,b'x'*600+b'\0')
            def mutate(kind,index,read,write):
                if kind=='malloc' and index==1:write(G+0x3000,b'y')
            s.effects.mutate=mutate
        elif label in ('provider_failure','free_failure'):
            def fail(tx,*a):_write_span(tx,G+0x5000,b'effect');raise RefillUnsupported('provider failure')
            kw['allocate' if label=='provider_failure' else 'free']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:model.print_json_unformatted(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_provider_effect_rollback_verified=False))
    return rows
def callback_guards(library,libc):
    import sys,vm9_diagnostics as diagnostics,vm9_libc_stdio as mutex
    import vm9_request_287474_vm as second
    v=sys.modules[__name__];image=BASES[0]
    LABELS=('wrong_target','unaligned_stack','missing_allocator','missing_free','unmapped_receiver','unmapped_output',
    'packed_spill','receiver_spill','output_spill','node_spill','allocation_spill','object_new_NULL','counter_new_NULL',
    'provider_failure','free_failure','guard_wait')
    rows=[]
    for label in LABELS:
        p,node=v.fixture(library,libc,image,'empty_object')
        v.w(p,image+diagnostics.GUARD,0x101);v.w(p,image+diagnostics.GLOBAL_LOCK,G+0x3500)
        v.w(p,G+0x3500,image+0x34C738);_write_span(p,G+0x3508,bytes(40))
        v.w(p,image+diagnostics.TABLE,G+0x800);v.w(p,G+0x3600,image+0x34C738)
        mutex.initialize_recursive_mutex(p,mutex_address=G+0x3608)
        for i in range(256):v.w(p,G+0x800+i*8,G+0x3600)
        block,receiver,output=G+0x1000,G+0x1800,G+0x1400
        v.w(p,block,image+0x2616B4);v.w(p,block+8,output);v.w(p,block+16,receiver);v.w(p,receiver+8,node)
        s=v.Services(failures=(2,) if label=='object_new_NULL' else (4,) if label=='counter_new_NULL' else ())
        kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,thread_pointer=v.TLS,allocate=s.malloc,free=s.free,thread_id=137)
        if label=='wrong_target':v.w(p,block,image+1)
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_free':kw['free']=None
        elif label=='unmapped_receiver':v.w(p,block+16,0x66000000)
        elif label=='unmapped_output':v.w(p,block+8,0x66000000)
        elif label=='packed_spill':kw['argument_block_address']=SP-32;_write_span(p,SP-32,v._read_span(p,block,24))
        elif label=='receiver_spill':v.w(p,block+16,SP-32)
        elif label=='output_spill':v.w(p,block+8,SP-16)
        elif label=='node_spill':v.w(p,receiver+8,SP-64)
        elif label=='allocation_spill':kw['allocate']=lambda tx,n:SP-64
        elif label in ('provider_failure','free_failure'):
            def fail(tx,*a):_write_span(tx,G+0x5000,b'effect');raise RefillUnsupported('provider failure')
            kw['allocate' if label=='provider_failure' else 'free']=fail
        elif label=='guard_wait':v.w(p,image+diagnostics.GUARD,0x200)
        before={k:bytes(b) for k,b in p.items()}
        try:second.apply_request_287474_json_print_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(b) for k,b in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_provider_effect_rollback_verified=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('native','guards','callback-guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    e=dict(cases=[],negative_cases=[])
    if a.mode=='callback-guards':e['negative_cases']=callback_guards(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library,a.libc)
    else:
        for image in BASES:
            for label in PROFILES:
                e['cases'].append(compare(a.library,a.libc,image,label));a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
