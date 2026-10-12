"""Fresh Base64 encoder, StringObject composition and actual request callback.

Guest alphabet, forward aliases, live source reloads, scratch, return and owning
effects are compared against original instructions. Allocator inputs are synthetic.
No native snapshot initializes Python; complete request/JNI/physical ABI is unproved.
"""
from pathlib import Path
import argparse,ast,hashlib,inspect,json,os
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import verify_vm9_request_prefix_fresh_20261007 as prefix
import vm9_objects as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SOURCE=G+0x1000;DEST=G+0x1100;LENGTH=G+0x1800;DATA=G+0x2000;BUFFER=G+0x2800
BASES=(0x122C0000,0x775C205000)


def fresh(library,base,length):
    p=dependency.fresh(library,base)
    _write_span(p,DATA,bytes((i*91+7)&255 for i in range(length)))
    for address,capacity,n,pointer in ((SOURCE,length+1,length,DATA),(DEST,1,0,BUFFER)):
        dependency.w(p,address,base+0x34F5F8);dependency.w(p,address+8,capacity,4)
        dependency.w(p,address+12,n,4);dependency.w(p,address+16,pointer)
    return p


def primitive_fixture(library,base,label):
    n=int(label[7:]) if label.startswith('length_') else 7
    p=fresh(library,base,n);dest=BUFFER;capacity=(n+2)//3*4+1;source=DATA;length=LENGTH
    if label=='query':dest=0;source=0x66000000
    elif label=='short_capacity':capacity-=1;source=0x66000000
    elif label=='overflow_query':n=(1<<64)-1;dest=0;source=0x66000000
    elif label=='large_query':n=1<<40;dest=0;source=0x66000000
    elif label=='changed_alphabet':_write_span(p,base+0x95C80,bytes(range(64)))
    elif label=='self_overlap':dest=DATA
    elif label=='destination_before_source':dest=DATA-2
    elif label=='alphabet_alias':dest=base+0x95C80
    elif label=='tail_alphabet_alias':n=2;dest=base+0x95C80+29
    elif label=='output_length_alias':length=dest+2
    return p,(dest,capacity,length,source,n)


def images(p,base):return {(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}


def compare_bytes(p,memory,observed,label):
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),own[i],memory[i]))
    for (a,n),data in observed.items():
        got=_read_span(p,a,n)
        if got!=data:
            i=next(i for i,(x,y) in enumerate(zip(got,data)) if x!=y)
            raise AssertionError((label,'observed',hex(a+i),got[i],data[i]))


def compare_primitive(library,base,label):
    p,args=primitive_fixture(library,base,label);observed=images(p,base)
    returned,memory,_,_=oracle.native(library,base,0x2456AC,list(args),p,
        observed_memory=observed,instruction_limit=150000)
    result=model.encode_configuration_base64(p,destination_address=args[0],destination_size=args[1],
        length_address=args[2],source_address=args[3],source_size=args[4],image_base=base)
    compare_bytes(p,memory,observed,label);assert returned&0xFFFFFFFF==result&0xFFFFFFFF
    print('PASS Base64 primitive',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_encoder_returned=True,
        status_length_and_all_guest_ELF_bytes_match=True,live_alphabet_forward_aliases_and_NUL_match=True,native_snapshot_input=False)


class Services(dependency.Services):
    def __init__(self,label,length):
        super().__init__(blocks={DATA:length+1,BUFFER:128 if label=='preallocated' else 1},
            failures=(0,) if label=='NULL_malloc' else ())
        self.label=label;self.changed=False
    def mutate(self,write):
        if self.changed:return
        self.changed=True
        if self.label=='source_grows':write(SOURCE+12,(7).to_bytes(4,'little'))
        elif self.label=='source_shrinks':write(SOURCE+12,(1).to_bytes(4,'little'))
        elif self.label=='source_pointer_changes':write(SOURCE+16,(DATA+1).to_bytes(8,'little'))
    def malloc(self,p,n):
        result=super().malloc(p,n);self.mutate(lambda a,b:_write_span(p,a,b));return result
    def native_malloc(self,c,n):
        result=super().native_malloc(c,n);self.mutate(lambda a,b:c.mem_write(a,b));return result


def outer_fixture(library,base,label):
    length=int(label[7:]) if label.startswith('length_') else 4
    p=fresh(library,base,length);dest=SOURCE if label=='self_alias' else DEST
    if label=='preallocated':dependency.w(p,DEST+8,128,4)
    _write_span(p,DATA+length,bytes(range(20)))
    return p,length,dest


def native_outer(library,base,p,s,source,dest,observed,wrapper=None):
    function=0x258D6C if wrapper is None else 0x285C94
    arguments=[source,dest] if wrapper is None else [wrapper]
    return oracle.native(library,base,function,arguments,p,malloc_handler=s.native_malloc,
        host_imports={0x347FA0:s.native_free,
            0x348320:lambda c:s.effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))},
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},
        observed_memory=observed,instruction_limit=150000)


def compare_outer(library,base,label):
    p,length,dest=outer_fixture(library,base,label);actual=Services(label,length);expected=Services(label,length)
    observed=images(p,base);observed[dependency.SP-0x40,16]=None
    returned,memory,_,_=native_outer(library,base,p,expected,SOURCE,dest,observed)
    result=model.encode_string_object_base64(p,source_object_address=SOURCE,object_address=dest,
        entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
        allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free)
    compare_bytes(p,memory,observed,label);assert returned==int(result)
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed
    print('PASS Base64 string',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_string_encoder_returned=True,
        boolean_return_full_guest_ELF_and_scratch_match=True,
        query_length_live_source_and_fill_effects_match=True,ordered_allocation_and_pre_free_bytes_match=True,native_snapshot_input=False)


def consumer(p,base,s,packed,source=None):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix) if source is None else source)
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    tx=prefix._PageTransaction(p);ns=dict(vars(prefix))
    ns.update(image=base,ledger=[],decoded=[],allocate=s.malloc,reallocate=s.effects.realloc,free=s.free,
        diagnostic_scope={},inputs={'thread_pointer':dependency.TP},
        frame=SimpleNamespace(native_stack_address=dependency.SP+0x180))
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:dependency.u(tx,a))),base+0x285C94,packed)
    tx.commit()


def compare_callback(library,base,label):
    p,length,dest=outer_fixture(library,base,'length_0' if label=='empty' else 'length_4')
    packed=G+0x1200
    if label=='self_alias':dest=SOURCE
    _write_span(p,packed,(base+0x258D6C).to_bytes(8,'little')+SOURCE.to_bytes(8,'little')+dest.to_bytes(8,'little')+b'\xA5'*8)
    actual=Services(label,length);expected=Services(label,length);observed=images(p,base)
    observed[dependency.SP-0x50,16]=None
    _,memory,_,_=native_outer(library,base,p,expected,SOURCE,dest,observed,packed)
    consumer(p,base,actual,packed)
    compare_bytes(p,memory,observed,label)
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.freed==expected.freed
    print('PASS Base64 source callback',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_string_encoder_wrapper_returned=True,
        source_callback_executed=True,packed_boolean_padding_and_full_guest_ELF_scratch_match=True,
        allocation_and_cleanup_match=True,native_snapshot_input=False)


def guards(library):
    rows=[];base=BASES[0]
    for label in ('unmapped_source','unmapped_target','negative_length','missing_provider','invalid_bound',
            'live_source_failure','TLS_canary_changed','unmapped_raw_output','unmapped_raw_length','unmapped_raw_alphabet'):
        p,length,dest=outer_fixture(library,base,'length_4');s=Services('default',length)
        kw=dict(source_object_address=SOURCE,object_address=dest,entry_stack_address=dependency.SP,
            image_base=base,thread_pointer=dependency.TP,allocate=s.malloc,reallocate=s.effects.realloc,free=s.free)
        if label=='unmapped_source':dependency.w(p,SOURCE+16,0x66000000)
        elif label=='unmapped_target':kw['object_address']=0x66000000
        elif label=='negative_length':dependency.w(p,SOURCE+12,0xFFFFFFFF,4)
        elif label=='missing_provider':kw['allocate']=None
        elif label=='invalid_bound':kw['max_bytes']=0
        elif label in ('live_source_failure','TLS_canary_changed'):
            def mutate(q,n):
                pointer=s.malloc(q,n)
                if label=='live_source_failure':dependency.w(q,SOURCE+16,0x66000000)
                else:_write_span(q,dependency.TP+0x28,bytes(8))
                return pointer
            kw['allocate']=mutate
        raw=label.startswith('unmapped_raw')
        if label=='unmapped_raw_alphabet':del p[(base+0x95C80)>>12]
        before={k:bytes(v) for k,v in p.items()}
        try:
            if raw:model.encode_configuration_base64(p,destination_address=0x66000000 if label=='unmapped_raw_output' else BUFFER,
                destination_size=32,length_address=0x66000000 if label=='unmapped_raw_length' else LENGTH,
                source_address=DATA,source_size=4,image_base=base)
            else:model.encode_string_object_base64(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS Base64 guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('primitive','outer','callback','guards','all'),default='primitive');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    raw=[];outer=[];callbacks=[];negative=[]
    if args.group in ('primitive','all'):
        profiles=tuple('length_'+str(n) for n in (0,1,2,3,4,7,32,128))+('query','short_capacity','overflow_query','large_query',
            'changed_alphabet','self_overlap','destination_before_source','alphabet_alias','tail_alphabet_alias','output_length_alias')
        raw=[compare_primitive(args.library,base,label) for base in BASES for label in profiles]
    if args.group in ('outer','all'):
        profiles=tuple('length_'+str(n) for n in (0,1,2,3,4,7,32))+('preallocated','self_alias','source_grows','source_shrinks','source_pointer_changes','NULL_malloc')
        outer=[compare_outer(args.library,base,label) for base in BASES for label in profiles]
    if args.group in ('callback','all'):callbacks=[compare_callback(args.library,base,label) for base in BASES for label in ('empty','nonempty','self_alias')]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request Base64 encode',primitive_cases=raw,outer_cases=outer,callback_cases=callbacks,
        native_Python_controls=len(raw)+len(outer)+len(callbacks),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        constructed_prefix_native_differential_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
