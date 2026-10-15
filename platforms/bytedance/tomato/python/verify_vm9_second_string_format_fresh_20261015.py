"""Fresh +28880c tail wrapper reusing the accepted +248908 string formatter.

Only packed W2 is supplied. Formats consuming ambient GP/FP arguments refuse.
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
PROFILES=('signed','minimum','wide_W2','unsigned','percent','literal','empty','single_string_long',
    'cross_page_packed','format_output_alias')


def fixture(library,libc,image,label):
    p=formatter_fixture(library,image,libc);block=G+0x2FEC if label=='cross_page_packed' else PACKED
    value=0xFFFFFFFF;fmt=b'%d';address=FMT;data=G+0x2000
    if label=='minimum':value=0x80000000
    elif label=='wide_W2':value=0xABCDEF0180000001
    elif label=='unsigned':fmt=b'%u'
    elif label=='percent':fmt=b'%%/%d/%%'
    elif label=='literal':fmt=b'fixed-literal'
    elif label=='empty':fmt=b''
    elif label=='single_string_long':fmt=b'%s';value=G+0x3000;_write_span(p,value,b'x'*80+b'\0')
    elif label=='format_output_alias':address=data
    string(p,DEST,image,b'',data);word(p,DEST+8,8,4);blocks={data:8}
    _write_span(p,address,fmt+b'\0')
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x248908,DEST,address,value))+b'\xa5'*16)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image),blocks


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
        if a-image in (0x28880C,0x248908,0x347F70):seen.add(a-image)
    def syscall(c,n):
        assert n==98;args=[c.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)]
        assert args[1]==129;wake.append(args);return 0
    oracle.native(library,image,0x28880C,[kw['argument_block_address']],p,libc=libc,
        host_imports=imports,malloc_handler=lambda c,n:effects.native(c,'malloc',n),syscall_handler=syscall,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TLS,
            arm.UC_ARM64_REG_X3:0xBADC0FFE,arm.UC_ARM64_REG_X4:0xDEADBEEF},
        instruction_observer=observe,observed_memory=watch,instruction_limit=300000)
    assert seen=={0x28880C,0x248908,0x347F70}
    return watch,effects,wake,steps[0]


def red(library,libc,table):
    assert not hasattr(model,'apply_request_287474_string_format_callback');rows=[]
    for image in BASES:
        p,kw,blocks=fixture(library,libc,image,'wide_W2');watch,effects,wake,steps=original(library,libc,image,p,kw,blocks,table)
        guest=watch[(G,0xA000)];length=int.from_bytes(guest[DEST-G+12:DEST-G+16],'little')
        pointer=int.from_bytes(guest[DEST-G+16:DEST-G+24],'little')
        assert guest[pointer-G:pointer-G+length]==b'-2147483647'
        rows.append(dict(image_base=hex(image),previous_string_format_callback_missing=True,
            original_wrapper_formatter_and_matching_libc_printf_returned=True,W2_zero_extension_observed=True,
            native_instructions=steps,native_snapshot_input=False))
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
    print('PASS second string format',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_wrapper_formatter_and_matching_libc_printf_returned=True,declared_guest_image_TLS_and_locale_bytes_equal=True,
        packed_bytes_and_following_padding_equal=True,ordered_allocation_reallocation_free_locale_effects_equal=True,
        only_one_W2_argument_supplied=True,CPU_X0_return_compared=False,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library,libc):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_object','missing_format','NULL_format','unsupported_conversion',
            'ambient_argument_required','missing_allocator','NULL_temporary','format_bound','packed_stack_alias','unaligned_stack'):
        p,kw,blocks=fixture(library,libc,BASES[0],'signed');effects=Effects(blocks=blocks)
        kw.update(allocate=effects.malloc,reallocate=effects.realloc,free=effects.free)
        if label=='wrong_target':word(p,PACKED,1)
        elif label=='missing_packed':kw['argument_block_address']=G+0x10000
        elif label=='missing_object':word(p,PACKED+8,G+0x10000)
        elif label=='missing_format':word(p,PACKED+16,G+0x10000)
        elif label=='NULL_format':word(p,PACKED+16,0)
        elif label=='unsupported_conversion':_write_span(p,FMT,b'%x\0')
        elif label=='ambient_argument_required':_write_span(p,FMT,b'%d/%d\0')
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='NULL_temporary':effects.failures={0}
        elif label=='format_bound':kw['max_bytes']=2
        elif label=='packed_stack_alias':
            _write_span(p,SP-0x200,_read_span(p,PACKED,32));kw['argument_block_address']=SP-0x200
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_string_format_callback(p,**kw)
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
