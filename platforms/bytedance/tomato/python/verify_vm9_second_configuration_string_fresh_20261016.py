"""Fresh guarded configuration string copy through the exact second wrapper.

Matching libc implements mutex transitions. Allocation failures and source
mutations are explicit synthetic services; native outputs never seed Python.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_registry as registry,vm9_request_287474_vm as second
import verify_vm9_registry as trees,verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;REG=G+0x8000
BASES=(0x122C0000,0x775C205000)
PROFILES=('empty_tree','missing_key','NULL_value','found_empty','found_binary','embedded_NUL',
    'negative_length','malloc_failure','missing_malloc_failure','cross_output','cross_packed',
    'cross_source','readers7','live_source_pointer')
GUARDS=('wrong_target','unaligned_stack','missing_packed','missing_output','missing_receiver',
    'missing_query','unknown_comparator','writer_count','saturated_readers','mutex_contention',
    'node_bound','byte_bound','missing_source','source_spill','payload_spill','allocation_spill',
    'invalid_allocation','provider_failure','provider_changes_constant','output_spill','key_spill','packed_spill',
    'output_wrapper_spill','payload_wrapper_spill')
def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def fixture(library,image,label):
    keys=[] if label=='empty_tree' else [b'a',b'b',b'c'];query=b'z' if label in ('missing_key','missing_malloc_failure') else b'b'
    p,blocks,addresses=trees.fixture(library,image,keys+[query]);effects=Effects(blocks=blocks)
    registry.construct_configuration_tree(p,container_address=REG+0x30,descriptor_address=trees.DESCRIPTOR,image_base=image,allocate=effects.malloc)
    _write_span(p,REG+0x80,bytes(0x98));output=G+(0x6FF8 if label=='cross_output' else 0x1800)
    block=G+(0x9FF0 if label=='cross_packed' else 0x1700)
    source=G+(0x6FF8 if label=='cross_source' else 0x6000);payload=G+0x6800
    data=b'' if label=='found_empty' else b'a\0tail' if label=='embedded_NUL' else b'\x80\xffdata'
    _write_span(p,source,(image+0x34F5F8).to_bytes(8,'little')+(len(data)+1).to_bytes(4,'little')+(0x80000000 if label=='negative_length' else len(data)).to_bytes(4,'little')+payload.to_bytes(8,'little'))
    _write_span(p,payload,data+b'\0');_write_span(p,G+0x6900,b'live!!\0')
    for i,(key,_,old_value) in enumerate(addresses[:-1]):
        value=0 if label=='NULL_value' and i==1 else source if i==1 else old_value
        registry.insert_configuration_pair(p,container_address=REG+0x30,key_address=key,value_address=value,
            image_base=image,allocate=effects.malloc,free=effects.free)
    w(p,REG+0x110,7 if label=='readers7' else 0,4)
    _write_span(p,output,b'\xA5'*24)
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x256CE0,output,REG,addresses[-1][0]))+b'\x5A'*8)
    return p,dict(argument_block_address=block,image_base=image,entry_stack_address=SP),effects.next,source
def services(label,image,next_address,source):
    s=Services(failures=(0,) if label in ('malloc_failure','missing_malloc_failure') else ())
    s.effects.next=next_address
    if label=='live_source_pointer':
        def mutate(kind,index,read,write):
            if kind=='malloc':write(source+16,(G+0x6900).to_bytes(8,'little'))
        s.effects.mutate=mutate
    def allocate(p,n):
        s.events.append(['reader',u(p,REG+0x110,4),u(p,REG+0x114,1)])
        return s.malloc(p,n)
    def native_allocate(cpu,n):
        s.events.append(['reader',int.from_bytes(cpu.mem_read(REG+0x110,4),'little'),cpu.mem_read(REG+0x114,1)[0]])
        return s.native_malloc(cpu,n)
    return s,allocate,native_allocate
def original(library,libc,image,p,kw,expected,native_allocate):
    seen=set();steps=[0];common={0x28890C,0x256CE0,0x25C168,0x1654E0,0x1654B4,0x32A444,0x32A4FC}
    def observe(cpu,a):
        steps[0]+=1
        if a-image in common|{0x2483E0,0x248344}:seen.add(a-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None,(SP-0x60,24):None,(kw['argument_block_address'],40):None})
    _,_,allocations,ledger=oracle.native(library,image,0x28890C,[kw['argument_block_address']],p,libc=libc,
        real_singletons=True,real_mutexes=True,malloc_handler=native_allocate,observed_memory=watch,
        instruction_limit=50000,instruction_observer=observe,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    assert common<=seen and len(seen-common)==1 and not allocations
    assert ledger==[[op,REG+0x88] for op in ('pthread_mutex_lock','pthread_mutex_unlock')*2]
    return watch,steps[0],0x2483E0 in seen
def compare(library,libc,image,label):
    p,kw,next_address,source=fixture(library,image,label);packed=_read_span(p,kw['argument_block_address'],40)
    expected,_,native_allocate=services(label,image,next_address,source);actual,allocate,_=services(label,image,next_address,source)
    watch,steps,found=original(library,libc,image,p,kw,expected,native_allocate)
    callback=getattr(second,'apply_request_287474_configuration_string_callback',None)
    assert callable(callback),'original guarded lookup constructs its string, but the second callback is missing'
    value=callback(p,allocate=allocate,**kw)
    assert value==u(p,kw['argument_block_address']+8)
    assert all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls,label
    assert actual.effects.blocks==expected.effects.blocks and _read_span(p,kw['argument_block_address'],40)==packed
    assert u(p,REG+0x110,4)==(7 if label=='readers7' else 0) and u(p,REG+0x114,1)==1
    print('PASS configuration string',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,found_nonNULL_value=found,
        original_wrapper_lookup_copy_or_empty_and_shared_reader_returned=True,
        declared_guest_image_and_scope_bytes_equal=True,packed_bytes_preserved=True,
        ordered_allocation_effects_and_reader_state_at_allocation_equal=True,four_actual_libc_mutex_transitions_equal=True,
        synthetic_allocation_services=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)
def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,kw,next_address,source=fixture(library,image,'missing_key' if label=='provider_changes_constant' else 'found_binary')
        s,allocate,_=services('zero',image,next_address,source);kw['allocate']=allocate;block=kw['argument_block_address']
        key=u(p,block+24)
        if label=='wrong_target':w(p,block,image+1)
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='missing_output':w(p,block+8,0x66000000)
        elif label=='missing_receiver':w(p,block+16,0x66000000)
        elif label=='missing_query':w(p,block+24,0x66000000)
        elif label=='unknown_comparator':w(p,REG+0x48,0)
        elif label in ('writer_count','saturated_readers'):w(p,REG+0x110,0x80000000 if label=='writer_count' else 0x7FFFFFFF,4)
        elif label=='mutex_contention':w(p,REG+0x88,2,2)
        elif label=='node_bound':kw['max_nodes']=1
        elif label=='byte_bound':kw['max_bytes']=1
        elif label in ('missing_source','source_spill'):
            tree=registry._ConfigurationTree(p,REG+0x30,image,4096,0x100000);pair=tree.u64(tree.find(key)+32)
            w(p,pair+8,0x66000000 if label=='missing_source' else SP-0x100)
        elif label=='payload_spill':w(p,source+16,SP-0x100)
        elif label=='payload_wrapper_spill':w(p,source+16,SP-16)
        elif label=='allocation_spill':kw['allocate']=lambda tx,n:SP-0x100
        elif label=='invalid_allocation':kw['allocate']=lambda tx,n:True
        elif label=='provider_failure':
            def fail(tx,n):_write_span(tx,G+0x5000,b'rollback');raise RefillUnsupported('provider failure')
            kw['allocate']=fail
        elif label=='provider_changes_constant':
            def mutate(kind,index,read,write):
                if kind=='malloc':write(image+0x6FE64,b'x')
            s.effects.mutate=mutate
        elif label=='output_spill':w(p,block+8,SP-0x100)
        elif label=='output_wrapper_spill':w(p,block+8,SP-16)
        elif label=='key_spill':w(p,block+24,SP-0x100)
        elif label=='packed_spill':
            kw['argument_block_address']=SP-0x100;_write_span(p,SP-0x100,_read_span(p,block,32))
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_configuration_string_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_provider_effect_rollback_verified=False))
    return rows
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('red','native','guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in (('found_binary',) if a.mode=='red' else PROFILES):
                e['cases'].append(compare(a.library,a.libc,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
