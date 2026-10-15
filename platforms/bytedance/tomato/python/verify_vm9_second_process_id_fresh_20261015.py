"""Fresh +28863c calls into matching-libc getpid/getppid, with explicit syscalls."""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;BLOCK=G+0x1200;LIBC=0x51000000
BASES=(0x122C0000,0x775C205000)
PROFILES={
    'pid_cached':('getpid',137,919), 'pid_cached_high_bit':('getpid',0xF1234567,-1),
    'pid_cold':('getpid',0,919), 'pid_cold_zero':('getpid',0,0),
    'pid_errno':('getpid',0,-1), 'pid_errno4095':('getpid',0,-4095),
    'pid_negative_nonerrno':('getpid',0,-4096), 'ppid':('getppid',137,17),
    'ppid_errno':('getppid',137,-13), 'ppid_wide_result':('getppid',137,0x123456789),
    'ppid_no_cache_access':('getppid',137,29), 'cross_page_result':('getpid',0,31)}


def exports(libc):
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        rows={s.name:LIBC+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name in ('getpid','getppid') and s['st_shndx']!='SHN_UNDEF'}
    assert set(rows)=={'getpid','getppid'}
    return rows


def fixture(library,libc,image,label):
    symbol,cached,raw=PROFILES[label];p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x6FF8 if label=='cross_page_result' else BLOCK
    bindings=exports(libc)
    _write_span(p,block,bindings[symbol].to_bytes(8,'little')+b'\xa6'*16)
    _write_span(p,TP+8,(G+0xC000 if label!='ppid_no_cache_access' else 0x66000000).to_bytes(8,'little'))
    _write_span(p,G+0xC014,cached.to_bytes(4,'little'))
    _write_span(p,TP+0x10,b'\x73'*8)
    return p,dict(argument_block_address=block,entry_stack_address=SP,thread_pointer=TP,
        import_bindings=bindings),symbol,cached,raw


def original(library,libc,image,p,kw,symbol,raw):
    steps=[0];seen=set();calls=[];bindings=kw['import_bindings']
    def syscall(cpu,number):
        assert number=={'getpid':172,'getppid':173}[symbol]
        calls.append([number,[]]);return raw
    def observe(cpu,address):
        steps[0]+=1
        if address==image+0x28863C:seen.add('wrapper')
        if address==bindings[symbol]:seen.add(symbol)
        if address==LIBC+0x23FB0:seen.add('errno')
        if address==LIBC+0x1F1F8:seen.add('__errno')
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x40):None,(SP,G+0x10000-SP):None,(TP+0x10,8):None})
    result,memory,allocations,ledger=oracle.native(library,image,0x28863C,[kw['argument_block_address']],p,
        libc=libc,syscall_handler=syscall,instruction_observer=observe,observed_memory=watch,
        instruction_limit=1000,extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert {'wrapper',symbol}<=seen and not allocations and not ledger
    assert ('errno' in seen)==('__errno' in seen)==bool(calls and -4095<=raw<0)
    return result,memory,watch,steps[0],calls


def red(library,libc):
    assert not hasattr(model,'apply_request_287474_process_id_callback')
    rows=[]
    for image in BASES:
        p,kw,symbol,cached,raw=fixture(library,libc,image,'pid_errno')
        result,memory,watch,steps,calls=original(library,libc,image,p,kw,symbol,raw)
        assert result==(1<<64)-1 and calls==[[172,[]]]
        assert watch[TP+0x10,8]==(1).to_bytes(4,'little')+b'\x73'*4
        rows.append(dict(image_base=hex(image),previous_PID_callback_missing=True,
            actual_wrapper_libc_syscall_errno_returned=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    p,kw,symbol,cached,raw=fixture(library,libc,image,label)
    result,memory,watch,steps,expected=original(library,libc,image,p,kw,symbol,raw);calls=[]
    def syscall(p,number,args):calls.append([number,list(args)]);return raw
    actual=model.apply_request_287474_process_id_callback(p,**kw,syscall=syscall)
    assert actual==result and calls==expected,label
    # Native spills occupy SP-0x30..SP. Compare every other guest byte.
    assert all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert _read_span(p,G+0xC014,4)==cached.to_bytes(4,'little'),label
    assert _read_span(p,kw['argument_block_address']+12,12)==b'\xa6'*12,label
    print('PASS second process ID',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,symbol=symbol,native_instructions=steps,
        actual_wrapper_and_matching_libc_returned=True,declared_guest_and_image_ranges_equal=True,
        X0_and_W32_packed_result_and_padding_equal=True,syscall_numbers_and_calls_equal=True,
        errno_and_adjacent_bytes_equal=True,cached_PID_unchanged=True,syscall_calls=len(calls),
        native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library,libc):
    rows=[]
    labels=('wrong_target','NULL_binding','duplicate_bindings','missing_packed','unaligned_stack',
        'invalid_thread_pointer','missing_cached_thread','missing_provider','invalid_syscall_result',
        'missing_errno_page','final_store_failure_after_provider','packed_spill_alias')
    for label in labels:
        p,kw,symbol,cached,raw=fixture(library,libc,BASES[0],'pid_cold')
        kw['syscall']=lambda p,n,a:919
        if label=='wrong_target':_write_span(p,BLOCK,(1).to_bytes(8,'little'))
        elif label=='NULL_binding':kw['import_bindings']=dict(kw['import_bindings'],getpid=0)
        elif label=='duplicate_bindings':kw['import_bindings']={'getpid':1,'getppid':1}
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='invalid_thread_pointer':kw['thread_pointer']=None
        elif label=='missing_cached_thread':_write_span(p,TP+8,(0x66000000).to_bytes(8,'little'))
        elif label=='missing_provider':kw['syscall']=None
        elif label=='invalid_syscall_result':kw['syscall']=lambda *a:1<<63
        elif label=='missing_errno_page':
            kw['thread_pointer']=0x66000000
            _write_span(p,BLOCK,kw['import_bindings']['getppid'].to_bytes(8,'little'))
            kw['syscall']=lambda *a:-13
        elif label=='final_store_failure_after_provider':
            block=G+0x9FF8;kw['argument_block_address']=block
            _write_span(p,block,kw['import_bindings']['getpid'].to_bytes(8,'little'));del p[(G+0xA000)>>12]
            def provider(p,n,a):_write_span(p,G+0x1800,b'changed');return 919
            kw['syscall']=provider
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x20
            _write_span(p,SP-0x20,kw['import_bindings']['getpid'].to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_process_id_callback(p,**kw)
        except (RefillUnsupported,TypeError,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library,a.libc)
    else:e['cases']=[compare(a.library,a.libc,b,n) for b in BASES for n in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
