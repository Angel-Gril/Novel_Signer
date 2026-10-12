"""Fresh forward byte-set search, field erase, left trim and actual consumer.

Shared bitmap semantics are preserved by expansion AST comparison. Fresh native
controls compare guest/image bytes, bitmap/canary, memmove aliases and statuses.
No accepted reverse-search native groups are repeated; full signing is unproved.
"""
from pathlib import Path
import argparse,ast,hashlib,inspect,json,os
from types import SimpleNamespace
from unicorn import arm64_const as arm
import verify_vm9_request_trim_set_fresh_20261013 as dependency
import verify_vm9_signer_objects as oracle
import verify_vm9_request_prefix_fresh_20261007 as prefix
import vm9_objects as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OBJ=dependency.OBJ;SET=dependency.SET;DATA=dependency.DATA
BASES=dependency.BASES;SP=dependency.dependency.SP;TP=dependency.dependency.TP
u=dependency.dependency.u;w=dependency.dependency.w


def fixture(library,base,label):
    p,set_object,length=dependency.fixture(library,base,label)
    data=None
    if label in ('leading_set','pattern_bitmap_alias'):data=b'=\0abc'
    elif label=='high_bytes':data=b'\x80\xFFab'
    elif label=='embedded_NUL':data=b'\0a\0b'
    if data is not None:_write_span(p,DATA,data+b'\0');w(p,OBJ+12,len(data),4);length=len(data)
    return p,set_object,length


def observed(p,base,scratch=None):
    result={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    if scratch is not None:result[scratch,40]=None
    return result


def compare_search(library,base,label):
    p,set_object,length=fixture(library,base,label);fields=OBJ+8;set_fields=set_object+8;position=0
    if label=='equal_position':position=length
    elif label=='before_end':position=1
    elif label=='negative_position':position=0xFFFFFFFF
    elif label=='beyond_length':position=length+1
    elif label=='NULL_receiver':fields=0
    elif label=='NULL_receiver_payload':w(p,OBJ+16,0)
    elif label=='NULL_set':set_fields=0
    elif label=='NULL_set_payload':w(p,SET+16,0)
    elif label=='pattern_bitmap_alias':w(p,SET+16,SP-0x58)
    watch=observed(p,base,SP-0x58)
    returned,memory,allocations,_=oracle.native(library,base,0x247894,[fields,position,set_fields],p,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_limit=20000)
    result=model.find_string_fields_first_not_in_set(p,fields_address=fields,position_u32=position,
        set_fields_address=set_fields,entry_stack_address=SP,image_base=base,thread_pointer=TP)
    dependency_compare(p,memory,watch,result,returned,allocations,label)
    return receipt(base,label,'forward_search')


def erase_fixture(library,base,label):
    p,_,_=fixture(library,base,'leading_set');fields=OBJ+8;position=0;count=2
    if label=='middle':position=2;count=1
    elif label=='suffix':position=3;count=100
    elif label=='all':count=0x7FFFFFFF
    elif label=='zero_count':count=0
    elif label=='past_end':position=20
    elif label=='negative_position':position=0xFFFFFFFF;count=3
    elif label=='negative_adjusted_count':position=0xFFFFFFFF;count=0
    elif label=='negative_position_wrapped_count':position=0xFFFFFFFF;count=0x80000000
    elif label=='NULL_fields':fields=0
    elif label=='NULL_payload':w(p,OBJ+16,0)
    elif label=='negative_length':w(p,OBJ+12,0xFFFFFFFF,4)
    elif label=='capacity_too_small':w(p,OBJ+8,1,4)
    elif label=='zero_capacity':w(p,OBJ+8,0,4)
    elif label=='payload_fields_alias':
        w(p,OBJ+8,20,4);w(p,OBJ+12,8,4);w(p,OBJ+16,OBJ+8);count=4
    return p,fields,position,count


def dependency_compare(p,memory,watch,result,returned,allocations,label):
    assert _read_span(p,G,0xA000)==memory,(label,'guest')
    assert result&0xFFFFFFFF==returned&0xFFFFFFFF and not allocations,(label,'return/effects')
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(label,'observed')


def receipt(base,label,kind):
    print('PASS left-set',hex(base),kind,label,flush=True)
    return dict(image_base=hex(base),case=label,kind=kind,original_returned=True,
        signed_status_full_guest_ELF_and_applicable_scratch_match=True,
        live_fields_length_NUL_and_memmove_semantics_match=True,no_allocator_effects=True,native_snapshot_input=False)


def compare_erase(library,base,label):
    p,fields,position,count=erase_fixture(library,base,label);watch=observed(p,base)
    returned,memory,allocations,_=oracle.native(library,base,0x247250,[fields,position,count],p,
        observed_memory=watch,instruction_limit=20000)
    result=model.erase_string_fields(p,fields_address=fields,position_u32=position,count_u32=count)
    dependency_compare(p,memory,watch,result,returned,allocations,label)
    return receipt(base,label,'erase')


def compare_trim(library,base,label):
    p,set_object,_=fixture(library,base,label);watch=observed(p,base,SP-0x78)
    returned,memory,allocations,_=oracle.native(library,base,0x248EB4,[OBJ,set_object],p,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_limit=20000)
    result=model.trim_string_object_left_set(p,object_address=OBJ,set_object_address=set_object,
        entry_stack_address=SP,image_base=base,thread_pointer=TP)
    dependency_compare(p,memory,watch,result,returned,allocations,label)
    return receipt(base,label,'left_trim')


def consumer(p,base,packed,source=None):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix) if source is None else source)
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    tx=prefix._PageTransaction(p);ns=dict(vars(prefix))
    ns.update(image=base,ledger=[],decoded=[],allocate=None,diagnostic_scope={},
        inputs={'thread_pointer':TP},frame=SimpleNamespace(native_stack_address=SP+0x180))
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:u(tx,a))),base+0x285B44,packed)
    tx.commit()


def compare_callback(library,base,label):
    p,set_object,_=fixture(library,base,label);packed=G+0x1200
    _write_span(p,packed,(base+0x248EB4).to_bytes(8,'little')+OBJ.to_bytes(8,'little')+set_object.to_bytes(8,'little')+b'\xA5'*8)
    watch=observed(p,base,SP-0x78)
    _,memory,allocations,_=oracle.native(library,base,0x285B44,[packed],p,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_limit=20000)
    consumer(p,base,packed)
    assert _read_span(p,G,0xA000)==memory and not allocations
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
    print('PASS left-set source callback',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_left_trim_wrapper_returned=True,source_callback_executed=True,
        packed_padding_and_full_guest_ELF_scratch_match=True,no_allocator_effects=True,native_snapshot_input=False)


def guards(library):
    rows=[];base=BASES[0]
    for label in ('unmapped_receiver','unmapped_pattern','unmapped_bitmap','invalid_position','invalid_stack',
            'invalid_bound','pattern_bound','receiver_bound','erase_unmapped_buffer','erase_bound','invalid_erase_word'):
        p,set_object,length=fixture(library,base,'leading_set')
        kw=dict(fields_address=OBJ+8,position_u32=0,set_fields_address=set_object+8,
            entry_stack_address=SP,image_base=base,thread_pointer=TP)
        if label=='unmapped_receiver':kw['fields_address']=0x66000000
        elif label=='unmapped_pattern':w(p,SET+16,0x66000000)
        elif label=='unmapped_bitmap':kw['entry_stack_address']=0x66000000
        elif label=='invalid_position':kw['position_u32']=1<<32
        elif label=='invalid_stack':kw['entry_stack_address']+=1
        elif label=='invalid_bound':kw['max_bytes']=0
        elif label=='pattern_bound':w(p,SET+12,65,4);kw['max_bytes']=64
        elif label=='receiver_bound':kw['max_bytes']=4
        elif label=='erase_unmapped_buffer':w(p,OBJ+16,0x66000000)
        before={k:bytes(v) for k,v in p.items()}
        try:
            if label.startswith('erase_') or label=='invalid_erase_word':model.erase_string_fields(p,fields_address=OBJ+8,
                position_u32=1<<32 if label=='invalid_erase_word' else 0,count_u32=2,max_bytes=1 if label=='erase_bound' else 0x100000)
            else:model.find_string_fields_first_not_in_set(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
        print('PASS left-set guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('search','erase','trim','callback','guards','all'),default='search');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    search=[];erase=[];trim=[];callbacks=[];negative=[]
    shared=('leading_set','no_match','all_set','empty_receiver','empty_set','duplicate_set','high_bytes','embedded_NUL')
    if args.group in ('search','all'):search=[compare_search(args.library,base,label) for base in BASES for label in shared+(
        'equal_position','before_end','negative_position','beyond_length','NULL_receiver','NULL_receiver_payload','NULL_set','NULL_set_payload','pattern_bitmap_alias')]
    if args.group in ('erase','all'):erase=[compare_erase(args.library,base,label) for base in BASES for label in (
        'prefix','middle','suffix','all','zero_count','past_end','negative_position','negative_adjusted_count','negative_position_wrapped_count',
        'NULL_fields','NULL_payload','negative_length','capacity_too_small','zero_capacity','payload_fields_alias')]
    if args.group in ('trim','all'):trim=[compare_trim(args.library,base,label) for base in BASES for label in shared+('same_object','exact_capacity','zero_capacity','negative_capacity')]
    if args.group in ('callback','all'):callbacks=[compare_callback(args.library,base,label) for base in BASES for label in ('leading_set','empty_receiver','same_object')]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request left character-set trim',search_cases=search,erase_cases=erase,trim_cases=trim,callback_cases=callbacks,
        native_Python_controls=len(search)+len(erase)+len(trim)+len(callbacks),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        constructed_prefix_native_differential_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
