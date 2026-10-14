"""Actual +2814c8/+204b80 wrapper and declared physical return controls."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_jni_availability_fresh_20261015 as shared
import vm9_request_caller as owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=shared.G;W=shared.SP+16;E=shared.SP;THREAD=G+0xD000
NAMES=('X30','SP','X0','X19','X28','X29','X30','X20','X21','X22')
FIELDS=('pc','sp','x0','x19','x28','x29','x30','x20','x21','x22')
OWNER='execute_request_jni_availability_wrapper'

def fixture(library,image,label):
    p,blocks=shared.fixture(library,image,label)
    packed=G+0x1000
    if label=='cross_page_packed':packed=G+0x1FF6
    offsets={'result_alias_helper_x20':-0x10,'result_alias_helper_x21':-0x18,
        'result_alias_helper_x22':-0x20,'result_alias_helper_fp':-0x30}
    if label in offsets:packed=E+offsets[label]-8
    _write_span(p,packed,(image+0x204B80).to_bytes(8,'little')+bytes.fromhex('1928374655647382'))
    inputs=dict(image_base=image,entry_stack_address=W,argument_block_address=packed,
        return_address=shared.oracle.STOP,thread_pointer=THREAD,saved_frame_pointer=G+0xCC00,
        saved_x19=G+0x8800,saved_x20=0x1234567812345678,
        saved_x21=0x2234567822345678,saved_x22=0x3234567832345678,saved_x28=G+0x8890)
    return p,blocks,inputs

def original(library,libc,p,inputs,services):
    image=inputs['image_base'];returns=[];seen=set()
    def observe(cpu,address):
        if address-image in (0x2814C8,0x204B80,0x204E48,0x2814D8,0x2814E0):seen.add(address-image)
        if address==image+0x2814E0:
            returns.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+n)) for n in NAMES))
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    if not services.label.startswith('cached_'):watch[E-0x60,16]=None
    watch[inputs['argument_block_address'],16]=None
    watch[E-0x38,0x48]=None
    extra={arm.UC_ARM64_REG_SP:W,arm.UC_ARM64_REG_TPIDR_EL0:THREAD,
        arm.UC_ARM64_REG_X29:inputs['saved_frame_pointer']}
    for n in (19,20,21,22,28):extra[getattr(arm,'UC_ARM64_REG_X'+str(n))]=inputs['saved_x'+str(n)]
    result,memory,_,_=shared.oracle.native(library,image,0x2814C8,[inputs['argument_block_address']],p,
        libc=libc,extra_registers=extra,real_singletons=True,real_mutexes=True,
        thread_id=137,real_jni_acquisition=True,host_imports=services.imports(),
        instruction_observer=observe,observed_memory=watch,
        malloc_handler=lambda cpu,n:services.vm.effects.native(cpu,'malloc',n),instruction_limit=200000)
    assert len(returns)==1 and returns[0][2]==result
    assert seen=={0x2814C8,0x204B80,0x204E48,0x2814D8,0x2814E0}
    return returns[0],memory,watch

def compare(library,libc,image,label,red=False):
    p,blocks,inputs=fixture(library,image,label);initial={k:bytearray(v) for k,v in p.items()}
    actual=shared.Services(image,blocks,label);expected=shared.Services(image,blocks,label)
    registers,memory,watch=original(library,libc,initial,inputs,expected)
    if red:
        assert not hasattr(owner,OWNER)
        return dict(image_base=hex(image),case=label,actual_helper_and_wrapper_returned=True,
            previous_wrapper_owner_missing=True,native_snapshot_input=False)
    state=getattr(owner,OWNER)(p,**inputs,acquire_environment=actual.acquire,invoke_jni=actual.model)
    assert registers==tuple(getattr(state,k) for k in FIELDS),(label,registers,state)
    assert _read_span(p,G,0xA000)==memory,label
    for (address,width),raw in watch.items():
        ours=_read_span(p,address,width)
        assert ours==raw,(label,hex(address-image),next((i for i,(a,b) in enumerate(zip(ours,raw)) if a!=b),None))
    assert actual.events==expected.events and actual.vm.events==expected.vm.events
    assert actual.vm.effects.calls==expected.vm.effects.calls and not actual.vm.responses and not expected.vm.responses
    print('PASS availability wrapper',hex(image),label,state.x0,flush=True)
    return dict(image_base=hex(image),case=label,actual_helper_and_wrapper_returned=True,
        ten_physical_return_values_equal=True,full_declared_guest_image_frame_and_packed_bytes_equal=True,
        packed_W_result_and_padding_equal=True,JavaVM_JNI_effects_equal=True,native_snapshot_input=False)

def guards(library):
    rows=[];image=shared.BASES[0]
    for label in ('wrong_target','unaligned_stack','tagged_return','missing_TLS','missing_packed',
            'canary_corruption','helper_LR_corruption','wrapper_LR_tagged','missing_JNI'):
        p,blocks,inputs=fixture(library,image,'uncached');service=shared.Services(image,blocks,'uncached')
        if label=='wrong_target':shared.w(p,inputs['argument_block_address'],image+1)
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='tagged_return':inputs['return_address']=1<<60
        elif label=='missing_TLS':inputs['thread_pointer']=G+0x10000
        elif label=='missing_packed':inputs['argument_block_address']=G+0x10000
        def invoke(staged,fn,args):
            result=service.model(staged,fn,args)
            if fn==shared.CHECK:
                if label=='canary_corruption':shared.w(staged,E-0x38,0)
                elif label=='helper_LR_corruption':shared.w(staged,E-0x28,image+1)
                elif label=='wrapper_LR_tagged':shared.w(staged,W-16,1<<60)
            return result
        before={k:bytes(v) for k,v in p.items()}
        try:getattr(owner,OWNER)(p,**inputs,acquire_environment=service.acquire,
            invoke_jni=None if label=='missing_JNI' else invoke)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_rolled_back=True))
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','all'),default='all');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==shared.oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==shared.acquisition.LIBC_SHA256
    e=dict(schema='vm9-request-jni-availability-wrapper-fresh-v1',evidence_date='2026-10-15',
        sample_sha256=shared.oracle.LIBRARY_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,
        complete_child_vm_verified=False,complete_second_vm_verified=False,complete_python_medusa=False,
        actual_URL_header_JNI_conversion_verified=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,live_Android_JVM_verified=False)
    labels=('uncached','cached_two','cached_255','exception_one','exception_high_only','null_environment',
        'cold_TLS','table_refresh','cross_page_packed','result_alias_helper_x20','result_alias_helper_x21',
        'result_alias_helper_x22','result_alias_helper_fp')
    if a.group=='red':e['red_cases']=[compare(a.library,a.libc,b,l,True) for b in shared.BASES for l in ('uncached','cached_255')]
    else:
        e['cases']=[compare(a.library,a.libc,b,l) for b in shared.BASES for l in labels]
        e['negative_cases']=guards(a.library)
    e['native_Python_controls']=len(e['cases']);e['rollback_guards']=len(e['negative_cases'])
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS availability wrapper',a.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
