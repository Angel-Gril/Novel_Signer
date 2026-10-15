"""Fresh +2888b4 five-argument tail wrapper reusing the accepted +248908 string formatter.

Packed W2 and four X arguments are supplied; further GP/FP arguments refuse.
Matching-libc vsnprintf executes; allocator effects remain explicit in components.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_request_287474_vm as model
import vm9_configuration_init as configuration
import verify_vm9_signer_objects as oracle
from verify_vm9_request_token_strings_fresh_20261013 import exports,string,word
from verify_vm9_shared_reference import fixture as formatter_fixture,TLS
from verify_vm9_strings import Effects
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;SP=G+0xEF00;PACKED=G+0x3800;DEST=G+0x1800;FMT=G+0x3500
BASES=(0x122C0000,0x775C205000)
LIBC_SHA256='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
PROFILES=('five_unsigned','mixed_width','upper_W2','long_string_tail','cross_page_packed',
    'format_output_alias','ignored_extra_words','long_aliases')


def fixture(library,libc,image,label):
    p=formatter_fixture(library,image,libc);block=G+0x2FD8 if label=='cross_page_packed' else PACKED
    values=[0xFEDCBA98FFFFFFFF,0x100000001,1<<63,(1<<64)-1,0]
    fmt=b'%lu|%llu|%llu|%llu|%llu';address=FMT;data=G+0x2000
    if label=='mixed_width':fmt=b'%d|%u|%lu|%llu|%d'
    elif label=='upper_W2':values[0]=0xABCDEF0180000001
    elif label=='long_string_tail':
        fmt=b'%lu|%llu|%llu|%llu|%s';values[-1]=G+0x3000;_write_span(p,values[-1],b'x'*80+b'\0')
    elif label=='format_output_alias':address=data
    elif label=='ignored_extra_words':fmt=b'fixed%%literal';values=[0x66000000+i*0x1000 for i in range(5)]
    elif label=='long_aliases':fmt=b'%lu/%lu/%llu/%lu/%llu'
    string(p,DEST,image,b'',data);word(p,DEST+8,8,4);blocks={data:8}
    _write_span(p,address,fmt+b'\0')
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x248908,DEST,address,*values))+b'\xa5'*16)
    assert label!='cross_page_packed' or block>>12!=(block+63)>>12
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image,wrapper_offset=0x2888B4),blocks


def original(library,libc,image,p,kw,blocks,table):
    effects=Effects(blocks=blocks);wake=[];steps=[0];seen=set()
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    for span in ((G,0xA000),(TLS,0xB00),(0x510DE930,16),(0x510E0200,0x800)):watch[span]=None
    imports={0x347FA0:lambda c:effects.native(c,'free',pointer=c.reg_read(arm.UC_ARM64_REG_X0)),
        0x348320:lambda c:effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))}
    def vsnprintf(c):c.reg_write(arm.UC_ARM64_REG_PC,table['vsnprintf'])
    imports[0x347F70]=vsnprintf
    def observe(c,a):
        steps[0]+=1
        if a-image in (0x2888B4,0x248908,0x347F70):seen.add(a-image)
    def syscall(c,n):
        assert n==98;args=[c.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)]
        assert args[1]==129;wake.append(args);return 0
    oracle.native(library,image,0x2888B4,[kw['argument_block_address']],p,libc=libc,
        host_imports=imports,malloc_handler=lambda c,n:effects.native(c,'malloc',n),syscall_handler=syscall,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TLS,
            arm.UC_ARM64_REG_X3:0xBADC0FFE,arm.UC_ARM64_REG_X4:0xDEADBEEF},
        instruction_observer=observe,observed_memory=watch,instruction_limit=300000)
    assert seen=={0x2888B4,0x248908,0x347F70}
    return watch,effects,wake,steps[0]


def red(library,libc,table):
    rows=[]
    for image in BASES:
        p,kw,blocks=fixture(library,libc,image,'five_unsigned')
        watch,effects,wake,steps=original(library,libc,image,p,kw,blocks,table)
        guest=watch[(G,0xA000)];length=int.from_bytes(guest[DEST-G+12:DEST-G+16],'little')
        pointer=int.from_bytes(guest[DEST-G+16:DEST-G+24],'little')
        assert guest[pointer-G:pointer-G+length]==b'4294967295|4294967297|9223372036854775808|18446744073709551615|0'
        actual=Effects(blocks=blocks);before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_string_format_callback(p,**{k:v for k,v in kw.items() if k!='wrapper_offset'},
            allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
        except RefillUnsupported as exc:assert 'printf conversion outside' in str(exc)
        else:raise AssertionError('prior formatter unexpectedly accepts long unsigned')
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(image_base=hex(image),previous_long_unsigned_conversion_rejected=True,
            original_five_argument_wrapper_and_matching_libc_printf_returned=True,
            first_W2_zero_extension_and_four_full_u64_arguments_observed=True,
            all_model_pages_unchanged_on_prior_rejection=True,native_instructions=steps,native_snapshot_input=False,
            accepted_native_controls_added=0))
    return rows


def compare(library,libc,image,label,table):
    p,kw,blocks=fixture(library,libc,image,label);watch,expected,expected_wake,steps=original(library,libc,image,p,kw,blocks,table)
    actual=Effects(blocks=blocks);wake=[]
    def prepare(p):configuration.prepare_bionic_format_locale(p,once_address=0x510DE938,key_address=0x510DE930,
        generation_table=0x510E0200,thread_pointer=TLS,wake=lambda p,*a:wake.append(list(a)) or 0)
    result=model.apply_request_287474_string_format_callback(p,**kw,
        allocate=actual.malloc,reallocate=actual.realloc,free=actual.free,prepare_format=prepare)
    assert result==DEST and all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),label
    assert actual.calls==expected.calls and actual.blocks==expected.blocks and wake==expected_wake,label
    print('PASS second five argument format',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_formatter_and_matching_libc_printf_returned=True,declared_guest_image_TLS_and_locale_bytes_equal=True,
        packed_bytes_and_following_padding_equal=True,ordered_allocation_reallocation_free_locale_effects_equal=True,
        first_W2_and_four_X_arguments_supplied=True,CPU_X0_return_compared=False,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library,libc):
    rows=[]
    for label in ('unknown_wrapper','sixth_argument','signed_long','triple_long','short_unsigned','size_t',
            'wide_float','long_incomplete','NULL_fifth_string','fifth_string_spill','packed_tail_spill',
            'missing_packed_tail','unsigned64_bound','provider_failure','missing_reallocator','invalid_long_word'):
        p,kw,blocks=fixture(library,libc,BASES[0],'five_unsigned');effects=Effects(blocks=blocks)
        kw.update(allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
        fmt={'sixth_argument':b'%llu/%llu/%llu/%llu/%llu/%llu','signed_long':b'%ld','triple_long':b'%lllu',
            'short_unsigned':b'%hu','size_t':b'%zu','wide_float':b'%Lf','long_incomplete':b'%ll',
            'NULL_fifth_string':b'%llu/%llu/%llu/%llu/%s'}
        if label in fmt:_write_span(p,FMT,fmt[label]+b'\0')
        if label=='unknown_wrapper':kw['wrapper_offset']=0x2888B8
        elif label=='NULL_fifth_string':word(p,PACKED+56,0)
        elif label=='fifth_string_spill':word(p,PACKED+56,SP-32)
        elif label=='packed_tail_spill':
            block=SP-0x1020;_write_span(p,block,_read_span(p,PACKED,64));kw['argument_block_address']=block
        elif label=='missing_packed_tail':
            block=G+0x2FD8;_write_span(p,block,_read_span(p,PACKED,64));del p[(G+0x3000)>>12];kw['argument_block_address']=block
        elif label=='unsigned64_bound':kw['max_bytes']=16
        elif label=='provider_failure':
            def allocate(p,n):
                _write_span(p,G+0x3600,b'rollback')
                raise RefillUnsupported('explicit format allocator failure after staged write')
            kw['allocate']=allocate
        elif label=='missing_reallocator':kw['reallocate']=None
        before={k:bytes(v) for k,v in p.items()}
        try:
            if label=='invalid_long_word':configuration._format_guest_strings(p,FMT,(-1,1,2,3,4),4096)
            else:model.apply_request_287474_string_format_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native','guards'),default='native');ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc,exports(a.libc))
    elif a.mode=='native':
        table=exports(a.libc)
        for b in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,a.libc,b,label,table))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:e['negative_cases']=guards(a.library,a.libc)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
