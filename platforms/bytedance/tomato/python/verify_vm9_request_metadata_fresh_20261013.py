"""Fresh request metadata formatting versus original +0x287168 instructions.

Compare return, all semantic guest/image bytes and allocation/publication effects.
Fixtures and allocator inputs are independent; no captured native state is used.
Physical callee spills, complete request and actual JNI remain outside this gate.
"""
from pathlib import Path
import argparse,hashlib,json,os
import ast,inspect
from types import SimpleNamespace
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_request_transform as model
import vm9_configuration_init as configuration
import verify_vm9_request_prefix_fresh_20261007 as prefix
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OBJ=G+0x1000;OUT1=G+0x1100;OUT2=G+0x1108
FMT1=G+0x2000;DATA=G+0x2100;FMT2=G+0x2200
BASES=(0x122C0000,0x775C205000)


def fixture(library,base,label):
    p=dependency.fresh(library,base)
    _write_span(p,OBJ,bytes(24));value={'one':1,'signed_min':0x80000000,'all_bits':0xFFFFFFFF}.get(label,0)
    dependency.w(p,OBJ,value,4);dependency.w(p,OBJ+8,OUT1);dependency.w(p,OBJ+16,OUT2)
    if label=='same_slot':dependency.w(p,OBJ+16,OUT1)
    elif label=='first_slot_input_alias':dependency.w(p,OBJ+8,OBJ)
    elif label=='second_slot_input_alias':dependency.w(p,OBJ+16,OBJ+8)
    elif label=='cross_page_slot':dependency.w(p,OBJ+8,G+0x1FFC)
    if label in ('warm','scalar_and_slot_change','second_format_change','constant_grows','format_pointer_change'):
        pc=base+0x287168;mask=(1<<64)-1
        delta=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF407DE8C)&mask
        table=base+0x383568
        for off in (0x28,0x80,0x98):dependency.w(p,(dependency.u(p,table+off)+delta)&mask,1,4)
        for off,a in ((0,FMT1),(0x70,DATA),(0x78,FMT2)):dependency.w(p,table+off,(a-delta)&mask)
        _write_span(p,FMT1,b'first:%s\0');_write_span(p,DATA,b'fixture\0');_write_span(p,FMT2,b'value:%u\0')
    return p


class Services(dependency.Services):
    def __init__(self,base,label):
        failures={'NULL_first':(0,),'NULL_second':(1,),'NULL_both':(0,1)}.get(label,())
        super().__init__(failures=failures);self.base=base;self.label=label;self.calls=0
    def mutate(self,write):
        self.calls+=1
        if self.calls!=1:return
        if self.label=='scalar_and_slot_change':
            write(OBJ,(0x80000000).to_bytes(4,'little'));write(OBJ+16,(G+0x1180).to_bytes(8,'little'))
        elif self.label=='second_format_change':write(FMT2,b'changed:%u\0')
        elif self.label=='constant_grows':write(DATA,b'a much longer fixture\0')
        elif self.label=='format_pointer_change':
            write(self.base+0x383568+0x78,bytes(8))
    def malloc(self,p,size):
        result=super().malloc(p,size);self.mutate(lambda a,b:_write_span(p,a,b));return result
    def native_malloc(self,c,size):
        result=super().native_malloc(c,size);self.mutate(lambda a,b:c.mem_write(a,b));return result


def compare(library,base,label):
    p=fixture(library,base,label);expected=Services(base,label);actual=Services(base,label)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    returned,memory,_,_=oracle.native(library,base,0x287168,[OBJ],p,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=150000)
    result=model.construct_request_metadata(p,object_address=OBJ,image_base=base,allocate=actual.malloc)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),own[i],memory[i]))
    for (a,n),data in observed.items():
        assert _read_span(p,a,n)==data,(label,'image',hex(a-base))
    assert returned&0xFFFFFFFF==result,(label,hex(returned),hex(result))
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert actual.effects.blocks==expected.effects.blocks
    print('PASS request metadata',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_metadata_returned=True,
        uint32_return_and_full_semantic_guest_ELF_bytes_match=True,
        two_output_Cstrings_and_ordered_allocation_match=True,
        cached_input_words_and_live_format_passes_match=True,native_snapshot_input=False)


def profiles():
    return ('zero','one','signed_min','all_bits','warm','same_slot','first_slot_input_alias',
        'second_slot_input_alias','cross_page_slot','scalar_and_slot_change','second_format_change',
        'constant_grows','format_pointer_change','NULL_first','NULL_second','NULL_both')


def compare_unsigned(library,base,value):
    p=dependency.fresh(library,base);_write_span(p,FMT1,b'%u\0')
    actual=dependency.Services();expected=dependency.Services()
    returned,memory,_,_=oracle.native(library,base,0x278314,[OUT1,FMT1,value],p,
        malloc_handler=expected.native_malloc,instruction_limit=150000)
    result=configuration.allocate_printf_cstring(p,output_pointer_address=OUT1,format_address=FMT1,
        argument_addresses=(value,),allocate=actual.malloc)
    assert _read_span(p,G,0xA000)==memory and result==returned&0xFFFFFFFF
    pointer=dependency.u(p,OUT1);data=str(value&0xFFFFFFFF).encode()+b'\0'
    assert _read_span(p,pointer,len(data))==data and result==len(data)-1
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    print('PASS unsigned printf',hex(base),hex(value),flush=True)
    return dict(image_base=hex(base),input_ABI_word=hex(value),original_unsigned_printf_returned=True,
        low32_unsigned_decimal_and_length_match=True,full_guest_bytes_and_allocation_match=True,native_snapshot_input=False)


def consumer(service,base,p,packed,source=None):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix) if source is None else source)
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    tx=prefix._PageTransaction(p);context={}
    ns=dict(vars(prefix));ns.update(image=base,ledger=[],decoded=[],allocate=service.malloc,
        free=None,diagnostic_scope=context)
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:dependency.u(tx,a))),base+0x285E8C,packed)
    tx.commit()
    return context['request_metadata'][0]['second_printf_uint32_return']


def compare_callback(library,base,label):
    p=fixture(library,base,'all_bits' if label=='all_bits' else 'zero');packed=G+0x1200
    _write_span(p,packed,(base+0x287168).to_bytes(8,'little')+OBJ.to_bytes(8,'little')+bytes(16))
    if label=='packed_output_alias':dependency.w(p,OBJ+16,packed)
    actual=Services(base,label);expected=Services(base,label)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    returned,memory,_,_=oracle.native(library,base,0x285E8C,[packed],p,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=150000)
    result=consumer(actual,base,p,packed)
    assert _read_span(p,G,0xA000)==memory and result==returned&0xFFFFFFFF
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    print('PASS metadata source callback',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_metadata_wrapper_returned=True,
        source_callback_executed=True,full_semantic_guest_ELF_bytes_and_allocation_match=True,native_snapshot_input=False)


def unsigned_guards(library):
    rows=[]
    for label,args in (('missing_unsigned_word',()),('negative_unsigned_word',(-1,)),('oversized_unsigned_word',(1<<64,))):
        p=dependency.fresh(library,BASES[0]);_write_span(p,FMT1,b'%u\0')
        before={k:bytes(v) for k,v in p.items()};service=dependency.Services()
        try:configuration.allocate_printf_cstring(p,output_pointer_address=OUT1,
            format_address=FMT1,argument_addresses=args,allocate=service.malloc)
        except RefillUnsupported:pass
        else:raise AssertionError('unsigned guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()} and not service.events
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS unsigned guard',label,flush=True)
    return rows


def guards(library):
    rows=[]
    for label in ('unmapped_input','unmapped_first_slot','unmapped_second_slot','missing_allocator',
            'allocator_failure_after_first','invalid_allocation','unmapped_buffer','invalid_bound','unsupported_format'):
        base=BASES[0];p=fixture(library,base,'warm');service=Services(base,'warm')
        kw=dict(object_address=OBJ,image_base=base,allocate=service.malloc)
        if label=='unmapped_input':kw['object_address']=0x66000000
        elif label=='unmapped_first_slot':dependency.w(p,OBJ+8,0x66000000)
        elif label=='unmapped_second_slot':dependency.w(p,OBJ+16,0x66000000)
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='allocator_failure_after_first':
            def fail(q,n):
                if service.calls:raise RefillUnsupported('injected second allocation failure')
                return service.malloc(q,n)
            kw['allocate']=fail
        elif label=='invalid_allocation':kw['allocate']=lambda p,n:1<<64
        elif label=='unmapped_buffer':kw['allocate']=lambda p,n:0x66000000
        elif label=='invalid_bound':kw['max_bytes']=0
        else:_write_span(p,FMT2,b'%x\0')
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_request_metadata(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request metadata guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','guards','callback','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[];unsigned=[];callbacks=[]
    if args.group in ('native','all'):rows=[compare(args.library,base,label) for base in BASES for label in profiles()]
    if args.group in ('native','all'):unsigned=[compare_unsigned(args.library,base,n) for base in BASES for n in (0,1,0x80000000,0x12345678FFFFFFFF)]
    if args.group in ('guards','all'):negative=guards(args.library)
    if args.group in ('callback','all'):
        callbacks=[compare_callback(args.library,base,label) for base in BASES for label in ('zero','all_bits','packed_output_alias')]
        negative.extend(unsigned_guards(args.library))
    args.output.write_text(json.dumps(dict(component='Request metadata allocated formatting',cases=rows,
        native_Python_controls=len(rows)+len(unsigned)+len(callbacks),unsigned_printf_cases=unsigned,callback_cases=callbacks,
        negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        complete_request_transform_caller=False,constructed_prefix_native_differential_verified=False,
        whole_request_native_differential_verified=False,actual_URL_header_JNI_conversion_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
