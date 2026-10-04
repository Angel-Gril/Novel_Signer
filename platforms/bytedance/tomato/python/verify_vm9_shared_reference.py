"""Fresh ELF native differences for shared/environment getters.

Private constants stay in guest memory. Host property/syscall/registration and
nonreusing allocator effects are explicit; no native output is a model input.
Only offsets, counts and equality results are exported.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X8, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0
import vm9_configuration_init as model
import vm9_objects as objects
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects
BASES=(0x122C0000,0x775C205000)
TLS=GUEST+0xA000
ERRNO=TLS+0x100
PROPERTY=GUEST+0xB800
OUTPUT=GUEST+0x1800
STACK=GUEST+0xEF00


def word(p,a,v,n=8): _write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fixture(library,base,libc=None):
    p=fresh_pages();p.update(image_pages(library,base))
    if libc:
        loaded=image_pages(libc,0x51000000)
        for address in (0x510DE930,0x510E0200):p[address>>12]=loaded[address>>12]
    word(p,base+0x3D1680,1,1);word(p,base+0x3D1678,GUEST+0x3000);word(p,GUEST+0x3000,GUEST+0x3100);_write_span(p,GUEST+0x3100,bytes(136))
    word(p,TLS+8,TLS+0x200);_write_span(p,TLS+0x200,bytes(0x900));word(p,TLS+0x210,137,4)
    return p


def compare(library,libc,base,entry,pages,*,sdk=None,output=OUTPUT,failures=(),register_mutation=None,register_result=0):
    actual=Effects(blocks={},failures=failures);expected=Effects(blocks={},failures=failures)
    observed={(p<<12,4096):None for p in pages if base<=p<<12<base+0x400000}
    observed[(TLS,0xB00)]=None
    if 0x510DE930>>12 in pages:
        for region in ((0x510DE930,4),(0x510DE938,4),(0x510E0200,141*16)):observed[region]=None
    actual_events=[];native_events=[];freed_actual=[];freed_native=[]
    def amalloc(p,n):
        actual_events.append(['allocate',n]);return actual.malloc(p,n)
    def nmalloc(c,n):
        native_events.append(['allocate',n]);return expected.native(c,'malloc',n)
    def afree(p,ptr):
        actual_events.append(['free',ptr]);freed_actual.append(_read_span(p,ptr,actual.blocks[ptr]));return actual.free(p,ptr)
    def nfree(c):
        ptr=c.reg_read(UC_ARM64_REG_X0);native_events.append(['free',ptr]);freed_native.append(bytes(c.mem_read(ptr,expected.blocks[ptr])));return expected.native(c,'free',pointer=ptr)
    def aproperty(p,name):
        actual_events.append(['property_find'])
        if sdk is not None:actual_events.append(['property_read'])
        return sdk
    def nfind(c):
        native_events.append(['property_find']);return PROPERTY if sdk is not None else 0
    def nread(c):
        assert c.reg_read(UC_ARM64_REG_X0)==PROPERTY and not c.reg_read(UC_ARM64_REG_X1)
        native_events.append(['property_read']);c.mem_write(c.reg_read(UC_ARM64_REG_X2),sdk+b'\0');return len(sdk)
    def syscall_result(number,args):
        if number in (48,56,79):return -2
        if number==57:return -9
        if number==198:return -97
        raise RefillUnsupported('unexpected virtual log syscall '+str(number))
    def asyscall(p,number,args):
        # Guest pathname pointers are compared; unused ABI registers are excluded.
        actual_events.append(['syscall',number,list(args)]);return syscall_result(number,args)
    def nsyscall(c,number):
        if number==98:
            assert c.reg_read(UC_ARM64_REG_X1)&0x7F==1
            native_events.append(['wake',c.reg_read(UC_ARM64_REG_X0),c.reg_read(UC_ARM64_REG_X1),c.reg_read(UC_ARM64_REG_X2)]);return 0
        widths={48:4,56:4,57:1,79:4,198:3}
        from unicorn.arm64_const import UC_ARM64_REG_X3
        rr=(UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)
        aa=tuple(c.reg_read(r) for r in rr[:widths[number]])
        native_events.append(['syscall',number,list(aa)]);return syscall_result(number,aa)
    def amkdir(p,path,mode):
        actual_events.append(['mkdir',path,mode]);word(p,ERRNO,17,4);return 0xFFFFFFFF
    def nmkdir(c):
        native_events.append(['mkdir',c.reg_read(UC_ARM64_REG_X0),c.reg_read(UC_ARM64_REG_X1)]);c.mem_write(ERRNO,(17).to_bytes(4,'little'));return 0xFFFFFFFF
    def aregister(p,destructor,obj,dso):
        actual_events.append(['atexit',destructor,obj,dso])
        if register_mutation: register_mutation(lambda a,b:_write_span(p,a,b))
        return register_result
    def nregister(c):
        aa=[c.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
        native_events.append(['atexit',*aa])
        if register_mutation: register_mutation(c.mem_write)
        return register_result&((1<<64)-1)
    def awake(p,ptr,operation,count):
        actual_events.append(['wake',ptr,operation,count]);return 0
    def prepare(p):
        model.prepare_bionic_format_locale(p,once_address=0x510DE938,key_address=0x510DE930,
            generation_table=0x510E0200,thread_pointer=TLS,wake=awake)
    exports={}
    with libc.open('rb') as f:
        for section in ELFFile(f).iter_sections():
            if section['sh_type']=='SHT_DYNSYM':
                exports.update({s.name:0x51000000+s['st_value'] for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'})
    def redirect(name):
        def call(c):c.reg_write(UC_ARM64_REG_PC,exports[name]);return None
        return call
    def mutex(c):
        assert c.reg_read(UC_ARM64_REG_X0)==base+0x3DF1EC
        return 0
    returned,memory,_,ledger=native(library,base,entry,[],pages,libc=libc,
        real_singletons=True,real_mutexes=True,thread_id=137,
        extra_registers={UC_ARM64_REG_X8:output,UC_ARM64_REG_TPIDR_EL0:TLS},
        observed_memory=observed,instruction_limit=300000,malloc_handler=nmalloc,
        syscall_handler=nsyscall,host_imports={0x347FA0:nfree,0x347EA0:nregister,
            0x3484A0:nmkdir,0x3481A0:lambda c:ERRNO,0x348250:nfind,0x348260:nread,
            0x347F70:redirect('vsnprintf'),0x3484B0:redirect('strtol'),0x347F00:mutex,0x347F10:mutex})
    common=dict(image_base=base,allocate=amalloc,free=afree,
        read_property=aproperty,syscall=asyscall,errno_address=ERRNO)
    if entry==0x26CDC4:
        got=model.construct_default_shared_reference(pages,entry_stack_address=STACK,**common)
    elif entry==0x26CD0C:
        got=model.get_inline_shared_reference(pages,output_reference_address=output,
            entry_stack_address=STACK,thread_id=137,register_destructor=aregister,**common)
    elif entry==0x25EE84:
        got=model.construct_environment_reference(pages,output_reference_address=output,
            entry_stack_address=STACK,thread_id=137,register_destructor=aregister,
            reallocate=actual.realloc,mkdir=amkdir,prepare_format=prepare,**common)
    elif entry==0x172D40:
        got=model.get_environment_service_reference(pages,image_base=base,allocate=amalloc,thread_id=137).wrapper_address
        assert got==returned,'service wrapper return'
    else:
        got=model.get_environment_constant(pages,image_base=base,entry_offset=entry)
        assert got==returned,'constant return'
    current=_read_span(pages,GUEST,0xA000)
    if current!=memory:
        i=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
        raise AssertionError(f'{entry:#x}: guest+{i:#x}')
    for (a,n),data in observed.items():
        current=_read_span(pages,a,n)
        if current!=data:
            i=next(i for i,(x,y) in enumerate(zip(current,data)) if x!=y)
            raise AssertionError(f'{entry:#x}: observed+{a+i-base:#x}')
    assert actual.calls==expected.calls,'allocator order'
    assert actual.blocks==expected.blocks,'live allocations'
    assert actual_events==native_events,(entry,'ordered external effects',actual_events,native_events)
    assert freed_actual==freed_native,'pre-free payload'
    return {'entry_offset':hex(entry),'image_base':hex(base),'guest_and_all_image_and_tls_match':True,
        'ordered_effects_and_live_allocations_match':True,'pre_free_bytes_match':True,
        'allocations':actual.allocation_index,'frees':len(freed_actual),'environment_effects':len(actual_events)-actual.allocation_index-len(freed_actual)}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[];negatives=[]
    for base in BASES:
        for sdk in (None,b'19',b'30'):
            for entry in (0x26CDC4,0x26CD0C,0x25EE84):
                p=fixture(a.library,base,a.libc)
                cases.append(compare(a.library,a.libc,base,entry,p,sdk=sdk))
        for entry in (0x172D40,0x2562DC,0x256330):
            p=fixture(a.library,base,a.libc);cases.append(compare(a.library,a.libc,base,entry,p))
    for base in BASES:
        ref=base+0x3DEE28
        for count in (None,0,1,2,0x7FFFFFFF,0x80000000,0xFFFFFFFF):
            for delta in (None,-8,0,8):
                p=fixture(a.library,base,a.libc);word(p,base+0x3DEE20,1,1)
                word(p,ref,GUEST+0x3300);word(p,ref+8,0 if count is None else GUEST+0x3800)
                if count is not None:word(p,GUEST+0x3800,count,4)
                out=OUTPUT if delta is None else ref+delta
                case=compare(a.library,a.libc,base,0x26CD0C,p,output=out)
                case.update(profile='warm_reference_copy',counter_value=count,output_alias_delta=delta);cases.append(case)
        for entry in (0x26CDC4,0x26CD0C):
            p=fixture(a.library,base,a.libc)
            case=compare(a.library,a.libc,base,entry,p,failures=(2,));case['profile']='result_string_payload_malloc_null';cases.append(case)
        for sdk in (b'0',b'-1',b'  +19suffix',b'21',b'2147483647'):
            p=fixture(a.library,base,a.libc)
            case=compare(a.library,a.libc,base,0x26CDC4,p,sdk=sdk);case['profile']='synthetic_sdk_decimal';cases.append(case)
        for entry in (0x172D40,0x2562DC,0x256330):
            p=fixture(a.library,base,a.libc)
            if entry==0x172D40:
                word(p,base+0x3D18D8,1,1);word(p,base+0x3D18D0,GUEST+0x3900)
            else:
                model.get_environment_constant(p,image_base=base,entry_offset=entry)
            case=compare(a.library,a.libc,base,entry,p);case['profile']='warm_environment_getter';cases.append(case)
        for variant in ('null_shared','atexit_return_ignored','atexit_mutation'):
            p=fixture(a.library,base,a.libc)
            if variant=='null_shared':
                word(p,base+0x3DEE20,1,1);_write_span(p,ref,bytes(16))
                case=compare(a.library,a.libc,base,0x25EE84,p)
            else:
                mutation=(lambda write:write(ref,bytes(8))) if variant=='atexit_mutation' else None
                case=compare(a.library,a.libc,base,0x26CD0C,p,register_result=-1 if variant=='atexit_return_ignored' else 0,register_mutation=mutation)
            case['profile']=variant;cases.append(case)
    for label in ('jni','unmapped_output','unaligned_stack','guard_recursive','new_object_null','new_count_null','live_log_open','interrupted_log_open','sdk_overflow','sdk_cold_singleton','sdk_instrumentation'):
        base=BASES[0];p=fixture(a.library,base,a.libc);effects=Effects(blocks={},failures=(1,) if label=='new_object_null' else (3,) if label=='new_count_null' else ())
        if label=='jni':word(p,base+0x3DEED8,GUEST+0x3500)
        if label=='guard_recursive':word(p,base+0x3DEE21,2,1)
        if label=='sdk_cold_singleton':word(p,base+0x3D1680,0,8)
        if label=='sdk_instrumentation':word(p,GUEST+0x3110,1);word(p,GUEST+0x3118,2)
        before={k:bytes(v) for k,v in p.items()}
        def unsupported_syscall(p,number,args):
            return 3 if label=='live_log_open' else -4 if label=='interrupted_log_open' else -2 if number==56 else -9 if number==57 else -97
        try:
            model.get_inline_shared_reference(p,output_reference_address=GUEST+0x100000 if label=='unmapped_output' else OUTPUT,
                entry_stack_address=STACK+1 if label=='unaligned_stack' else STACK,image_base=base,
                allocate=effects.malloc,free=effects.free,read_property=lambda p,n:b'2147483648' if label=='sdk_overflow' else b'30' if label in ('sdk_cold_singleton','sdk_instrumentation') else None,
                syscall=unsupported_syscall,errno_address=ERRNO,thread_id=137,register_destructor=lambda *a:0)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in p.items()}==before,label+' page rollback'
            negatives.append({'case':label,'rejected':True,'guest_page_rollback':True,'external_effects_rollback_claimed':False})
        else:raise AssertionError(label+' accepted')
    for label,fmt,args_native,bound in (("unsupported_printf",b"%u",(GUEST+0x3500,),0x100000),
            ("incomplete_printf",b"%",(),0x100000),("missing_printf_argument",b"%s",(),0x100000),
            ("formatter_bound",b"%s",(GUEST+0x3500,),16)):
        p=fixture(a.library,BASES[0],a.libc);_write_span(p,GUEST+0x3600,fmt+b'\0');_write_span(p,GUEST+0x3500,b'synthetic\0')
        word(p,GUEST+0x3300,BASES[0]+0x34F5F8);word(p,GUEST+0x3308,8,4);word(p,GUEST+0x330C,0,4);word(p,GUEST+0x3310,GUEST+0x3700)
        effects=Effects(blocks={GUEST+0x3700:8});before={k:bytes(v) for k,v in p.items()}
        try:
            model.format_string_object(p,object_address=GUEST+0x3300,format_address=GUEST+0x3600,
                argument_addresses=args_native,image_base=BASES[0],allocate=effects.malloc,reallocate=effects.realloc,free=effects.free,max_bytes=bound)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in p.items()}==before,label+' page rollback'
            negatives.append({'case':label,'rejected':True,'guest_page_rollback':True,'external_effects_rollback_claimed':False})
        else:raise AssertionError(label+' accepted')
    report={'library_sha256':LIBRARY_SHA256,'native_differences':len(cases),'negative_count':len(negatives),'cases':cases,'negative_cases':negatives,
        'fresh_synthetic_inputs':True,'native_outputs_used_as_model_input':False,'jvm_used':False,
        'complete_python_medusa':False,'scope':'shared/environment helpers; state VM is verified separately',
        'initialized_singleton136_synthetic_fixture':True,'physical_spill_frames_excluded':True,
        'libc_format_locale_once_key_generation_and_wake_compared':True,
        'host_boundaries':['nonreusing_malloc_free','property_find_read','virtual_unavailable_files_socket','virtual_mkdir','destructor_registration','libc_no_waiter_futex_wake']}
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'native_differences':len(cases),'negative_count':len(negatives)}))

if __name__=='__main__':main()
