"""Original +28874c second wrapper reusing the measured child u32 lookup owner."""
from pathlib import Path
import argparse,ast,hashlib,json
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import vm9_request_287474_vm as second
import vm9_request_28048c_vm as child
import verify_vm9_request_child_registry_read_fresh_20261015 as prior
from vm9_allocator import _read_span

BASES=(0x122C0000,0x775C205000)
PROFILES=('empty','found_max','found_high_bit','cross_page_packed','packed_value_alias','guard_status_value_alias')

def wrapper_identity(library):
    with library.open('rb') as stream:
        section=ELFFile(stream).get_section_by_name('.text')
        data=section.data();start=section['sh_addr']
        a=data[0x28874C-start:0x28876C-start];b=data[0x28156C-start:0x28158C-start]
        assert len(a)==32 and a==b
    return hashlib.sha256(a).hexdigest()

def original(library,libc,image,label):
    p,kw,readers=prior.fixture(library,image,label)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch[prior.SP-0x60,24]=None;seen=set();steps=[0]
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28874C,0x256A18,0x1654E0,0x1654B4,0x32A444,0x32A4FC):seen.add(address-image)
    result,memory,allocations,ledger=prior.oracle.native(library,image,0x28874C,[kw['argument_block_address']],p,
        libc=libc,real_singletons=True,real_mutexes=True,observed_memory=watch,
        instruction_observer=observe,instruction_limit=50000,extra_registers={arm.UC_ARM64_REG_SP:prior.SP})
    assert not allocations and ledger==[[operation,prior.REGISTRY+0x88] for operation in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
    assert seen=={0x28874C,0x256A18,0x1654E0,0x1654B4,0x32A444,0x32A4FC}
    return p,kw,readers,result,memory,watch,steps[0]

def red(library,libc):
    assert not any(isinstance(n,ast.Constant) and n.value==0x28874C for n in ast.walk(ast.parse(Path(second.__file__).read_bytes())))
    rows=[]
    for image in BASES:
        p,kw,readers,result,memory,watch,steps=original(library,libc,image,'found_max')
        offset=kw['argument_block_address']-prior.G
        assert result==0xFFFFFFFF and memory[offset+24:offset+32]==b'\xff'*4+b'\xa5'*4
        rows.append(dict(image_base=hex(image),second_dispatch_missing=True,reused_child_owner_already_present=True,
            original_second_wrapper_and_getter_returned=True,W32_result_and_padding_observed=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,libc,image,label):
    p,kw,readers,result,memory,watch,steps=original(library,libc,image,label)
    value=child.apply_request_28048c_registry_read_callback(p,**kw)
    assert result==value and _read_span(p,prior.G,0xA000)==memory,label
    assert all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert int.from_bytes(_read_span(p,prior.REGISTRY+0x110,4),'little')==readers
    assert _read_span(p,prior.REGISTRY+0x114,1)==b'\1'
    assert _read_span(p,kw['argument_block_address']+28,4)==b'\xa5'*4
    print('PASS second registry read',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,
        original_second_wrapper_getter_and_readers_returned=True,reused_child_composition=True,
        all_declared_guest_image_and_scope_bytes_equal=True,W32_result_and_padding_equal=True,
        four_actual_mutex_transitions_equal=True,reader_count_restored_and_flag_retained=True,
        no_allocation_or_JNI_services=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native'),default='native')
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==prior.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==prior.LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],wrapper_bytes_equal_to_accepted_child=True,
        wrapper_bytes_sha256=wrapper_identity(a.library),complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    else:e['cases']=[compare(a.library,a.libc,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
