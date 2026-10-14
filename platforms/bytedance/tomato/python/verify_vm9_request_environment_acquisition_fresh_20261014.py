"""Actual +205058 wrapper with original environment acquisition and VM services.

TLS, allocation, JavaVM and temporary attach/detach use the existing owners.
Imported providers are explicit; this does not establish Android JVM behavior.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_jni_environment_fresh_20261007 as env_fixture
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
import vm9_jni_environment as environment
import vm9_request_environment_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST
OWNER='apply_request_environment_acquisition_callback'
PROFILES=('warm','cold_owner','cold_slots','cold_destructor','temporary_getenv',
    'temporary_attach_detach','cross_page_pair','packed_pair_alias')

def fixture(library,image,label):
    pages,blocks=env_fixture.fixture(library,image,
        guard=0 if label in ('cold_owner','cold_destructor') else 1,
        tls_cold=label=='cold_slots',destructor_guard=0 if label=='cold_destructor' else 1)
    block=G+0x1900;pair=G+0x1A00;env=G+0x3300
    if label=='cross_page_pair':pair=G+0x6FF8
    elif label=='packed_pair_alias':pair=block
    responses=((0,env),(0,env)) if label in ('cold_owner','cold_destructor','cold_slots') else ((-2,0),(0,env)) if label=='temporary_getenv' else ((-2,0),(-2,0)) if label=='temporary_attach_detach' else ((0,env),)
    _write_span(pages,block,(image+0x26EDC4).to_bytes(8,'little')+pair.to_bytes(8,'little')+b'\x91'*16)
    inputs=dict(argument_block_address=block,image_base=image,entry_stack_address=env_fixture.SP)
    return pages,inputs,blocks,responses

def run_native(library,libc,pages,inputs,provider,*,wrapper_offset=0x205058):
    watched={(page<<12,4096):None for page in pages if inputs['image_base']<=page<<12<inputs['image_base']+0x400000}
    counts={}
    def observe(cpu,address):
        if address-inputs['image_base'] in (wrapper_offset,0x26EDC4,0x34377C,0x34265C):
            offset=address-inputs['image_base'];counts[offset]=counts.get(offset,0)+1
    _,memory,_,_=oracle.native(library,inputs['image_base'],wrapper_offset,[inputs['argument_block_address']],pages,
        libc=libc,real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,
        host_imports=provider.imports(),instruction_observer=observe,observed_memory=watched,
        malloc_handler=lambda cpu,n:provider.effects.native(cpu,'malloc',n),instruction_limit=250000,
        extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address']})
    assert counts[wrapper_offset]==counts[0x26EDC4]==1
    return memory,watched,counts

def red(library,libc):
    assert not hasattr(model,OWNER)
    rows=[]
    for image in BASES:
        pages,inputs,blocks,responses=fixture(library,image,'warm')
        provider=env_fixture.Providers(image,Effects(blocks=blocks),responses)
        run_native(library,libc,pages,inputs,provider)
        assert not provider.responses
        rows.append(dict(image_base=hex(image),original_wrapper_and_acquisition_returned=True,
            prior_consumer_missing=True,acquisition_stub_disabled=True,native_snapshot_input=False))
    return rows

def compare(library,libc,image,label,*,wrapper_offset=0x205058):
    pages,inputs,blocks,responses=fixture(library,image,label);initial={k:bytearray(v) for k,v in pages.items()}
    actual=env_fixture.Providers(image,Effects(blocks=blocks),responses,attach=(0,G+0x3300))
    expected=env_fixture.Providers(image,Effects(blocks=blocks),responses,attach=(0,G+0x3300))
    def acquire(p,**kw):
        return environment.acquire_thread_environment(p,image_base=image,**kw,
            get_tls=actual.tls,register_destructor=actual.register,invoke_javavm=actual.model_vm)
    result=getattr(model,OWNER)(pages,**inputs,acquire_environment=acquire)
    memory,watched,counts=run_native(library,libc,initial,inputs,expected,wrapper_offset=wrapper_offset)
    assert _read_span(pages,G,0xA000)==memory,label
    assert all(_read_span(pages,a,n)==raw for (a,n),raw in watched.items()),label
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls,label
    assert not actual.responses and not expected.responses and result.environment==G+0x3300
    print('PASS environment acquisition wrapper',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,original_wrapper_and_acquisition_returned=True,
        actual_wrapper=hex(wrapper_offset),acquisition_stub_disabled=True,
        all_declared_guest_and_image_bytes_equal=True,allocation_TLS_and_JavaVM_order_equal=True,
        temporary_attach_detach=label=='temporary_attach_detach',native_snapshot_input=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','missing_pair','unaligned_stack','provider_late_failure','noncallable_provider'):
        pages,inputs,blocks,responses=fixture(library,BASES[0],'warm');block=inputs['argument_block_address']
        if label=='wrong_target':_write_span(pages,block,(BASES[0]+1).to_bytes(8,'little'))
        elif label=='missing_packed':del pages[block>>12]
        elif label=='missing_pair':_write_span(pages,block+8,(G+0x10000).to_bytes(8,'little'))
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        before={k:bytes(v) for k,v in pages.items()}
        actual=env_fixture.Providers(BASES[0],Effects(blocks=blocks),responses)
        def acquire(p,**kw):
            if label=='provider_late_failure':
                _write_span(p,G+0x4000,b'changed');raise RefillUnsupported('explicit acquisition failure')
            return environment.acquire_thread_environment(p,image_base=BASES[0],**kw,
                get_tls=actual.tls,register_destructor=actual.register,invoke_javavm=actual.model_vm)
        try:getattr(model,OWNER)(pages,**inputs,acquire_environment=None if label=='noncallable_provider' else acquire)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows

def entry_guards(library):
    os.environ['TOMATO_LIBMETASEC']=str(library.resolve());import vm_full
    from verify_vm9_request_environment_vm_fresh_20261013 import fixture as frames,packed
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[]
    for label in ('noncallable_provider','zero_budget','bounded_budget'):
        pages,inputs=frames(library,BASES[0],'normal');packed(pages,inputs);before={k:bytes(v) for k,v in pages.items()}
        kw=dict(vm_module=vm_full,acquire_environment=lambda *a,**k:None)
        if label=='noncallable_provider':kw['acquire_environment']=1
        elif label=='zero_budget':kw['maxsteps']=0
        else:kw['maxsteps']=1
        previous=vm_full.B
        try:model.execute_request_environment_vm_prefix(pages,argument_block_address=G+0x1000,**inputs,**kw)
        except RefillUnsupported:assert label!='bounded_budget'
        except RuntimeError as exc:assert label=='bounded_budget' and str(exc).startswith('step limit @')
        else:raise AssertionError(label)
        assert previous==vm_full.B and before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,module_image_base_restored=True))
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--libc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','wrappers','guards','entry','all'),default='all');a=p.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==env_fixture.LIBC_SHA256
    e=dict(schema='vm9-request-environment-acquisition-fresh-v1',evidence_date='2026-10-14',sample_sha256=oracle.LIBRARY_SHA256,
        cases=[],negative_cases=[],entry_negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_request_native_differential_verified=False,complete_helper_vm_verified=False,complete_child_vm_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,whole_physical_stack_bytes_compared=False,
        allocator_provider_mapping_rollback_verified=False)
    if a.group=='red':e['red_cases']=red(a.library,a.libc)
    if a.group in ('wrappers','all'):e['cases']=[compare(a.library,a.libc,image,label) for image in BASES for label in PROFILES]
    if a.group in ('guards','all'):e['negative_cases']=guards(a.library)
    if a.group in ('entry','all'):e['entry_negative_cases']=entry_guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS environment acquisition',a.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
