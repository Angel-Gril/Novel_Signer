"""Fresh complete request suffix composition versus the original helper.

All semantic guest/image bytes, output slots and ordered ownership effects
are compared. Physical stack spills and native X0 void return are excluded.
Allocator and initialized SDK are explicit independently constructed inputs.
"""
from pathlib import Path
import argparse,hashlib,json,os
import ast,inspect
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_request_transform_fresh_20261012 as fixture_owner
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_request_transform as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import verify_vm9_request_prefix_fresh_20261007 as prefix

G=oracle.GUEST;OBJ=G+0x1000;OUT1=G+0x1100;OUT2=G+0x1108;SEED=G+0x1200
BASES=(0x122C0000,0x775C205000)


def fresh(library,base,label):
    length=int(label[7:]) if label.startswith('length_') else 20
    p=fixture_owner.fresh(library,base,length,0)
    _write_span(p,OBJ,bytes(64))
    for offset,value in ((0,0x12345678),(8,fixture_owner.SOURCE),(16,fixture_owner.SOURCE),(24,SEED),(32,OUT1),(40,OUT2)):
        dependency.w(p,OBJ+offset,value)
    dependency.w(p,SEED,0x1234,2);dependency.w(p,base+0x3D18F8,1);dependency.w(p,base+0x3D18EC,0x11223344,4)
    if label.startswith('mode_one'):
        dependency.w(p,OBJ+48,1,4);dependency.w(p,OBJ+8,0x66000000);dependency.w(p,OBJ+16,0x66000000)
    elif label=='mode_all_bits':dependency.w(p,OBJ+48,0xFFFFFFFF,4)
    elif label=='NULL_MD5_source':dependency.w(p,fixture_owner.SOURCE+16,0)
    if label in ('warm_constants','mode_one_short_constant'):
        for address,data,flag in ((0x3E0FF0,b'x' if label.startswith('mode_one') else b'fixture',0x3E1004),
                (0x3E1008,b'[%s]',0x3E100C),(0x3E1010,b'marker',0x3E101C)):
            _write_span(p,base+address,data+b'\0');dependency.w(p,base+flag,1,4)
    if label=='seed_zero':dependency.w(p,SEED,0,2)
    elif label=='seed_all_bits':dependency.w(p,SEED,0xFFFF,2)
    elif label=='timestamp_high_bits':dependency.w(p,OBJ,0xFEDCBA9876543210)
    elif label=='same_output_slot':dependency.w(p,OBJ+40,OUT1)
    return p


def native(library,libc,base,p):
    service=dependency.Services();observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    def watch(cpu,address):
        offset=address-base
        if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if offset==0x348310:service.diagnostic('gettid',137)
        if offset==0x161068:service.events.append(['singleton136'])
    _,memory,_,_=oracle.native(library,base,0x2869F0,[OBJ],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},
        host_imports={0x347FA0:service.native_free,
            0x348320:lambda c:service.effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))},
        malloc_handler=service.native_malloc,instruction_observer=watch,observed_memory=observed,instruction_limit=250000)
    return memory,observed,service


def invoke(p,service,base,changes=None):
    def singleton(q):service.events.append(['singleton136']);return fixture_owner.WRAPPER
    kw=dict(object_address=OBJ,entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
        allocate=service.malloc,reallocate=service.effects.realloc,free=service.free,get_singleton=singleton,
        parse_decimal=lambda p,a:0,thread_id=137,diagnostic_observer=service.diagnostic)
    kw.update(changes or {})
    return model.construct_request_suffix(p,**kw)


def compare(library,libc,base,label):
    p=fresh(library,base,label);memory,observed,expected=native(library,libc,base,p);actual=dependency.Services()
    output=invoke(p,actual,base)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),hex(own[i]),hex(memory[i])))
    for (a,n),data in observed.items():
        if _read_span(p,a,n)!=data:
            got=_read_span(p,a,n);i=next(i for i,(x,y) in enumerate(zip(got,data)) if x!=y)
            raise AssertionError((label,'image',hex(a-base+i),got[i],data[i]))
    assert actual.events==expected.events,(label,'effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed,(label,'pre-free bytes',[(hex(a),b.hex()) for a,b in actual.freed],[(hex(a),b.hex()) for a,b in expected.freed])
    assert output==tuple(dependency.u(p,dependency.u(p,OBJ+i)) for i in (32,40))
    print('PASS request suffix',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_outer_suffix_returned=True,
        full_semantic_guest_and_ELF_bytes_match=True,output_Cstring_slots_and_contents_match=True,
        ordered_allocation_locks_and_cleanup_match=True,pre_free_bytes_match=True,native_snapshot_input=False)


def profiles():
    return tuple('length_'+str(n) for n in (0,1,2,7,32))+('mode_one','mode_one_short_constant','mode_all_bits',
        'warm_constants','seed_zero','seed_all_bits','timestamp_high_bits','same_output_slot')


def compare_raw_free(library,base,label):
    p=dependency.fresh(library,base);packed=G+0x1000
    pointer=0 if label=='NULL' else packed if label=='packed_alias' else G+0x2000
    blocks={pointer:32} if pointer else {}
    _write_span(p,packed,(base+0x347FA0).to_bytes(8,'little')+pointer.to_bytes(8,'little')+b'\xA5'*16)
    if pointer!=packed and pointer:_write_span(p,pointer,b'\xA5'*32)
    expected=dependency.Services(blocks);actual=dependency.Services(blocks)
    _,memory,_,_=oracle.native(library,base,0x285910,[packed],p,
        host_imports={0x347FA0:expected.native_free},instruction_limit=100)
    # Execute the actual source callback body with independent current pages.
    # Only the VM dispatch is isolated; no duplicate Python callback is used.
    tree=ast.parse(inspect.getsource(prefix.execute_prefix))
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    namespace=dict(vars(prefix));namespace.update(image=base,ledger=[],allocate=None,free=actual.free,diagnostic_scope={})
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),namespace)
    vm=SimpleNamespace(m=SimpleNamespace(pages=p,u64=lambda a:dependency.u(p,a)))
    namespace['callback'](vm,base+0x285910,packed)
    assert _read_span(p,G,0xA000)==memory
    assert actual.events==expected.events and actual.freed==expected.freed
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert namespace['diagnostic_scope']['request_final_frees']==[dict(completed=True)]
    print('PASS request raw free',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_raw_free_wrapper_returned=True,
        source_callback_executed=True,full_guest_bytes_and_ordered_free_match=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('unaligned_stack','unmapped_input','unmapped_seed','unmapped_output','nonzero_SDK',
            'unsupported_transform','missing_allocate','missing_decimal','invalid_bound'):
        base=BASES[0];p=fresh(library,base,'length_7');service=dependency.Services();kw={}
        if label=='unaligned_stack':kw['entry_stack_address']=dependency.SP-1
        elif label=='unmapped_input':kw['object_address']=0x66000000
        elif label=='unmapped_seed':dependency.w(p,OBJ+24,0x66000000)
        elif label=='unmapped_output':dependency.w(p,OBJ+32,0x66000000)
        elif label=='nonzero_SDK':dependency.w(p,fixture_owner.SDK+16,1)
        elif label=='unsupported_transform':dependency.w(p,base+0x383540,0)
        elif label=='missing_allocate':kw['allocate']=None
        elif label=='missing_decimal':kw['parse_decimal']=None
        else:kw['max_bytes']=1
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,service,base,kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request suffix guard',label,flush=True)
    return rows


def raw_free_guards(library):
    rows=[]
    for label in ('missing_provider','provider_failure'):
        base=BASES[0];p=dependency.fresh(library,base);packed=G+0x1000
        _write_span(p,packed,(base+0x347FA0).to_bytes(8,'little')+(G+0x2000).to_bytes(8,'little'))
        def reject(q,a):
            _write_span(q,a,bytes(8));raise RefillUnsupported('injected raw free provider failure')
        tx=prefix._PageTransaction(p);tree=ast.parse(inspect.getsource(prefix.execute_prefix))
        callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
        ns=dict(vars(prefix));ns.update(image=base,ledger=[],allocate=None,
            free=None if label=='missing_provider' else reject,diagnostic_scope={})
        exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
        before={k:bytes(v) for k,v in p.items()}
        try:ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:dependency.u(tx,a))),base+0x285910,packed)
        except RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request raw free guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','raw_free','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[];free_rows=[];free_negative=[]
    if args.group in ('native','all'):rows=[compare(args.library,args.libc,base,label) for base in BASES for label in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    if args.group in ('raw_free','all'):
        free_rows=[compare_raw_free(args.library,base,label) for base in BASES for label in ('NULL','buffer','packed_alias')]
        free_negative=raw_free_guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request outer suffix composition',cases=rows,
        native_Python_controls=len(rows)+len(free_rows),negative_cases=negative,rollback_guards=len(negative)+len(free_negative),native_input_snapshot_used=False,
        raw_free_cases=free_rows,raw_free_negative_cases=free_negative,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        constructed_prefix_native_differential_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
