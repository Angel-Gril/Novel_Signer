"""Fresh reverse byte-set search, right trim and actual request consumer.

Compare full semantic guest/image bytes, bitmap/canary scratch, signed return
and exact length/NUL writes. Synthetic fixtures are independent native inputs.
Physical spills, actual JNI and whole-request signing remain unproved.
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

G=oracle.GUEST;OBJ=G+0x1000;SET=G+0x1100;DATA=G+0x2000;PATTERN=G+0x2100
BASES=(0x122C0000,0x775C205000)


def fixture(library,base,label):
    p=dependency.fresh(library,base);data=b'abc==\0';pattern=b'=\0';set_object=SET
    if label=='no_match':data=b'abc';pattern=b'z'
    elif label=='all_set':data=b'==\0='
    elif label=='empty_receiver':data=b''
    elif label=='empty_set':pattern=b''
    elif label=='duplicate_set':pattern=b'==\0==\0'
    elif label=='high_bytes':data=b'ab\x80\xFF';pattern=b'\x80\xFF'
    elif label=='embedded_NUL':data=b'a\0b\0';pattern=b'\0'
    for a,raw,ptr in ((OBJ,data,DATA),(SET,pattern,PATTERN)):
        dependency.w(p,a,base+0x34F5F8);dependency.w(p,a+8,len(raw)+4,4)
        dependency.w(p,a+12,len(raw),4);dependency.w(p,a+16,ptr);_write_span(p,ptr,raw+b'\0')
    if label=='same_object':set_object=OBJ
    elif label=='exact_capacity':dependency.w(p,OBJ+8,len(data),4)
    elif label=='zero_capacity':dependency.w(p,OBJ+8,0,4)
    elif label=='negative_capacity':dependency.w(p,OBJ+8,0xFFFFFFFF,4)
    return p,set_object,len(data)


def compare(library,base,label,*,outer):
    p,set_object,length=fixture(library,base,label);fields=OBJ+8;set_fields=set_object+8;position=max(0,length-1)
    if not outer:
        if label=='equal_position':position=length
        elif label=='before_end':position=1
        elif label=='negative_position':position=0xFFFFFFFF
        elif label=='beyond_length':position=length+1
        elif label=='NULL_receiver':fields=0
        elif label=='NULL_receiver_payload':dependency.w(p,OBJ+16,0)
        elif label=='NULL_set':set_fields=0
        elif label=='NULL_set_payload':dependency.w(p,SET+16,0)
        elif label=='pattern_bitmap_alias':dependency.w(p,SET+16,dependency.SP-0x58)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[dependency.SP-(0x78 if outer else 0x58),40]=None
    arguments=[OBJ,set_object] if outer else [fields,position,set_fields]
    returned,memory,allocations,_=oracle.native(library,base,0x248EF8 if outer else 0x24795C,arguments,p,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},observed_memory=observed,instruction_limit=20000)
    common=dict(entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP)
    result=model.trim_string_object_right_set(p,object_address=OBJ,set_object_address=set_object,**common) if outer else model.find_string_fields_last_not_in_set(p,
        fields_address=fields,position_u32=position,set_fields_address=set_fields,**common)
    assert _read_span(p,G,0xA000)==memory and result&0xFFFFFFFF==returned&0xFFFFFFFF
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()) and not allocations
    print('PASS right-set',hex(base),'trim' if outer else 'search',label,flush=True)
    return dict(image_base=hex(base),case=label,original_returned=True,
        signed_result_full_guest_ELF_bitmap_canary_match=True,
        length_NUL_and_live_byte_set_semantics_match=True,no_allocator_effects=True,native_snapshot_input=False)


def consumer(p,base,packed,source=None):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix) if source is None else source)
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    tx=prefix._PageTransaction(p);ns=dict(vars(prefix))
    ns.update(image=base,ledger=[],decoded=[],allocate=None,diagnostic_scope={},
        inputs={'thread_pointer':dependency.TP},frame=SimpleNamespace(native_stack_address=dependency.SP+0x180))
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:dependency.u(tx,a))),base+0x285B44,packed)
    tx.commit()


def compare_callback(library,base,label):
    p,set_object,_=fixture(library,base,label);packed=G+0x1200
    _write_span(p,packed,(base+0x248EF8).to_bytes(8,'little')+OBJ.to_bytes(8,'little')+set_object.to_bytes(8,'little')+b'\xA5'*8)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[dependency.SP-0x78,40]=None
    _,memory,allocations,_=oracle.native(library,base,0x285B44,[packed],p,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},observed_memory=observed,instruction_limit=20000)
    consumer(p,base,packed)
    assert _read_span(p,G,0xA000)==memory and not allocations
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items())
    print('PASS right-set source callback',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_trim_wrapper_returned=True,source_callback_executed=True,
        packed_padding_and_full_guest_ELF_scratch_match=True,no_allocator_effects=True,native_snapshot_input=False)


def guards(library):
    rows=[];base=BASES[0]
    for label in ('unmapped_receiver','unmapped_pattern','unmapped_bitmap','invalid_position','invalid_stack',
            'invalid_bound','pattern_bound','receiver_bound','unmapped_termination'):
        p,set_object,length=fixture(library,base,'trailing_set')
        kw=dict(fields_address=OBJ+8,position_u32=length-1,set_fields_address=set_object+8,
            entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP)
        if label=='unmapped_receiver':kw['fields_address']=0x66000000
        elif label=='unmapped_pattern':dependency.w(p,SET+16,0x66000000)
        elif label=='unmapped_bitmap':kw['entry_stack_address']=0x66000000
        elif label=='invalid_position':kw['position_u32']=1<<32
        elif label=='invalid_stack':kw['entry_stack_address']+=1
        elif label=='invalid_bound':kw['max_bytes']=0
        elif label=='pattern_bound':dependency.w(p,SET+12,65,4);kw['max_bytes']=64
        elif label=='receiver_bound':kw['max_bytes']=4
        elif label=='unmapped_termination':dependency.w(p,SET+12,0,4);dependency.w(p,OBJ+16,0x66000000)
        before={k:bytes(v) for k,v in p.items()}
        try:
            if label=='unmapped_termination':model.trim_string_object_right_set(p,object_address=OBJ,set_object_address=SET,
                entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP)
            else:model.find_string_fields_last_not_in_set(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
        print('PASS right-set guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('search','trim','callback','guards','all'),default='search');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    search=[];trim=[];callbacks=[];negative=[]
    shared=('trailing_set','no_match','all_set','empty_receiver','empty_set','duplicate_set','high_bytes','embedded_NUL')
    if args.group in ('search','all'):
        search=[compare(args.library,base,label,outer=False) for base in BASES for label in
            shared+('equal_position','before_end','negative_position','beyond_length','NULL_receiver','NULL_receiver_payload','NULL_set','NULL_set_payload','pattern_bitmap_alias')]
    if args.group in ('trim','all'):
        trim=[compare(args.library,base,label,outer=True) for base in BASES for label in shared+('same_object','exact_capacity','zero_capacity','negative_capacity')]
    if args.group in ('callback','all'):callbacks=[compare_callback(args.library,base,label) for base in BASES for label in ('trailing_set','empty_receiver','same_object')]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request right character-set trim',search_cases=search,trim_cases=trim,callback_cases=callbacks,
        native_Python_controls=len(search)+len(trim)+len(callbacks),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        constructed_prefix_native_differential_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
