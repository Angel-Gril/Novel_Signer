"""Fresh differential controls for actual executor shared release and libc exit.

All allocator, callback controls, TLS getters and OS results are explicit.
Owned guest mappings are actually removed in both native Unicorn and Python.
No live requests, captured pages, decoded tables or private payloads are saved.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X8,UC_ARM64_REG_X30,UC_ARM64_REG_TPIDR_EL0)
import vm9_allocator as allocator
import vm9_startup as startup
import vm9_thread_exit as exit_model
import verify_vm9_root_configuration as root
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from verify_vm9_thread_key_cleanup import fresh,key,TABLE,WORKER_TLS
from verify_vm9_startup_worker_loop import put,get
from verify_vm9_strings import Effects

CB0=GUEST+0xf200;CB1=GUEST+0xf210;CONTINUE=GUEST+0xf400
HEAD=GUEST+0x1000;CXA=GUEST+0x1100;CLEANUP=GUEST+0x1500
TREE=GUEST+0x2400;NODE=GUEST+0x2500;FHEAD=GUEST+0x3400;FLAG=GUEST+0x3480


def read(cpu,a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
def write(cpu,a,v,n=8):cpu.mem_write(a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def inputs(seed):return {k:v for k,v in seed.items() if not root.LIBC_BASE<=k<<12<root.LIBC_BASE+0x400000}


def shared_case(library,libc,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    for pages in (p,seed):put(pages,GUEST+0x1010,0)
    actual=[];expected=[];allocations=[];blocks={};phases=[0]
    effects=Effects(blocks={})
    def alloc(cpu,size,pointer):
        allocations.append([size,pointer]);blocks[pointer]=size;expected.append(['allocate',size,pointer])
    def allocate(pages,size):
        pointer=effects.malloc(pages,size);actual.append(['allocate',size,pointer]);return pointer
    def nfree(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);expected.append(['free',pointer])
        cpu.mem_write(pointer,bytes([0xd7])*blocks.pop(pointer));return 0
    def free(pages,pointer):actual.append(['free',pointer]);effects.free(pages,pointer)
    def ncreate(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X1)==0
        handle=GUEST+0xc800;write(cpu,cpu.reg_read(UC_ARM64_REG_X0),handle)
        expected.append(['create',cpu.reg_read(UC_ARM64_REG_X2),cpu.reg_read(UC_ARM64_REG_X3),handle]);return 0
    def create(pages,output,attributes,start,arg):
        assert attributes==0;handle=GUEST+0xc800;put(pages,output,handle)
        actual.append(['create',start,arg,handle]);return 0
    def nregister(cpu):
        expected.append(['register',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]]);return 0
    def register(pages,function,arg,dso):actual.append(['register',function,arg,dso]);return 0
    def njoin(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X1)==0
        expected.append(['join',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def join(pages,handle):actual.append(['join',handle]);return 0
    def changes(read,write):
        owner=read(base+0x3e2db0)
        if label=='weak_one':write(owner+16,1)
        if label=='weak_u64max':write(owner+16,(1<<64)-1)
        if label=='shared_u64max':write(owner+8,(1<<64)-1)
        if label=='null_handle':write(base+0x3e2db8+16,0)
    rounds=1 if label in ('old_shared_one','shared_u64max') else 2
    registered=label=='registered_destructor';weak=label!='shared_only'
    def continuation(cpu):
        if phases[0]==0:changes(lambda a:read(cpu,a),lambda a,v:write(cpu,a,v))
        if phases[0]==rounds:
            cpu.reg_write(UC_ARM64_REG_PC,STOP);return None
        phases[0]+=1
        argument=base+0x3e2da8 if registered else read(cpu,base+0x3e2db0)
        cpu.reg_write(UC_ARM64_REG_X0,argument);cpu.reg_write(UC_ARM64_REG_X30,CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC,base+(0x326984 if registered else 0x329eb4 if weak else 0x329e64));return None
    observed={(WORKER_TLS,0xc00):None}
    observed.update({(k<<12,4096):None for k in p if base<=k<<12<base+0x400000})
    _,memory,_,_=native(library,base,0x326710,[GUEST+0x1000],inputs(seed),libc=libc,
        real_singletons=True,real_mutexes=True,thread_id=137,allocation_effect=alloc,
        extra_registers={UC_ARM64_REG_X8:GUEST+0x1000,UC_ARM64_REG_X30:CONTINUE,UC_ARM64_REG_TPIDR_EL0:WORKER_TLS},
        host_imports={0x348000:ncreate,0x347ea0:nregister,0x347fa0:nfree,0x348610:njoin,CONTINUE-base:continuation},
        observed_memory=observed,instruction_limit=40000)
    startup.get_executor_reference(p,output_reference_address=GUEST+0x1000,scratch_address=GUEST+0x1010,
        image_base=base,allocate=allocate,create_thread=create,register_destructor=register,thread_id=137)
    changes(lambda a:get(p,a),lambda a,v:put(p,a,v))
    owner=get(p,base+0x3e2db0)
    for _ in range(rounds):
        if registered:startup.invoke_registered_thread_destructor(p,function_address=base+0x326984,
            object_address=base+0x3e2da8,image_base=base,free=free,join_thread=join)
        else:startup.release_executor_shared(p,owner_address=owner,image_base=base,
            free=free,join_thread=join,release_weak=weak)
    assert allocator._read_span(p,GUEST,0xa000)==memory,('executor guest',label)
    assert all(allocator._read_span(p,a,n)==v for (a,n),v in observed.items()),('executor image/TLS',label)
    assert actual==expected,('executor ordered effects',label,actual,expected)
    assert len(allocations)==4 and phases[0]==rounds
    return dict(case=label,image_base=hex(base),actual_constructor_vtable=True,
        actual_shared_zero_destructor=label not in ('old_shared_one','shared_u64max'),fresh_constructor_and_release_composed=True,
        ordered_effects_match=True,guest_image_tls_match=True,
        join_calls=sum(e[0]=='join' for e in actual),free_calls=sum(e[0]=='free' for e in actual),
        explicit_allocator_and_join=True,associated_support_state_destructor=False,native_input_snapshot_used=False)


def setup(library,libc,base,label):
    p=fresh(library,libc,base);os=allocator.GuestOS(p)
    detached=label.startswith('detached') or label in ('middle','tail','head','mixed_keys','main_os_failure')
    state={'already_exited':1,'already_joined':2,'other_state':4}.get(label,3 if detached else 0)
    region=None;alternate=None
    if label in ('detached_region','detached_struct_in_region','joinable_region','main_os_failure'):
        region=os.map_anonymous(0x6000,anonymous_name=b'thread-stack')
    if label in ('altstack','alt_os_failure','detached_struct_in_region'):
        alternate=os.map_anonymous(0x5000,anonymous_name=b'thread-altstack')
    thread=region.base+0x200 if label=='detached_struct_in_region' else WORKER_TLS+0x200
    if label=='detached_struct_in_region':allocator._write_span(p,thread,bytes(0xc00))
    put(p,WORKER_TLS+8,thread);put(p,thread+0x50,state,4);put(p,thread+0x70,0)
    put(p,thread+0x20,region.base if region else 0);put(p,thread+0xa8,region.length if region else 0)
    put(p,thread+0x78,alternate.base if alternate else 0)
    put(p,root.LIBC_BASE+0xe01d0,0,4);put(p,root.LIBC_BASE+0xe01f8,thread)
    put(p,thread,0);put(p,thread+8,0);put(p,HEAD,0);put(p,thread+0x58,0)
    if label in ('head','middle'):put(p,thread,GUEST+0x2100);put(p,GUEST+0x2108,thread)
    if label in ('tail','middle'):
        put(p,thread+8,GUEST+0x2000);put(p,GUEST+0x2000,thread);put(p,root.LIBC_BASE+0xe01f8,GUEST+0x2000)
    if label in ('cxa_one','cxa_three','cxa_publish','cxa_clear','cxa_real_tree','register_then_exit'):
        count=3 if label=='cxa_three' else 1
        if label!='register_then_exit':
            put(p,HEAD,CXA)
            for index in range(count):
                node=CXA+index*32;put(p,node,base+0x268cf0 if label=='cxa_real_tree' else CB0)
                put(p,node+8,TREE if label=='cxa_real_tree' else GUEST+0x1200+index*16)
                put(p,node+16,0x55);put(p,node+24,node+32 if index+1<count else 0)
    if label in ('cleanup_one','cleanup_two','cleanup_publish','cleanup_clear','cleanup_real_tree'):
        count=2 if label in ('cleanup_two','cleanup_clear') else 1
        put(p,thread+0x58,CLEANUP)
        for index in range(count):
            node=CLEANUP+index*24;put(p,node,node+24 if index+1<count else 0)
            put(p,node+8,base+0x268cf0 if label=='cleanup_real_tree' else CB1)
            put(p,node+16,TREE if label=='cleanup_real_tree' else GUEST+0x1600+index*16)
    if label in ('cxa_real_tree','cleanup_real_tree','mixed_keys'):
        put(p,TREE+8,NODE);put(p,NODE,0);put(p,NODE+8,0)
    if label=='mixed_keys':
        wrapper=GUEST+0x3000;support=GUEST+0x3100;array=GUEST+0x3200
        put(p,wrapper,support);allocator._write_span(p,support,bytes(48))
        key(p,1,value=wrapper,destructor=base+0x32ce6c)
        key(p,2,value=array,destructor=base+0x3439bc);put(p,base+0x3e31f4,0x80000002,4)
        put(p,array,1);put(p,array+8,0)
        key(p,3,value=1,destructor=base+0x342854)
        put(p,FHEAD,GUEST+0x3500);put(p,FLAG,1)
        put(p,GUEST+0x3500,base+0x268cf0);put(p,GUEST+0x3508,TREE);put(p,GUEST+0x3510,0)
    if label=='fallback_executor':
        owner=GUEST+0x2600;payload=GUEST+0x2700
        put(p,base+0x3e2da8,payload);put(p,base+0x3e2db0,owner)
        put(p,owner,base+0x372670);put(p,owner+8,0);put(p,owner+16,0);put(p,owner+24,payload)
        put(p,payload,base+0x372648);put(p,payload+16,0)
        key(p,3,value=1,destructor=base+0x342854)
        put(p,FHEAD,GUEST+0x3500);put(p,FLAG,1)
        put(p,GUEST+0x3500,base+0x326984);put(p,GUEST+0x3508,base+0x3e2da8);put(p,GUEST+0x3510,0)
    return p,os,thread


def exit_case(library,libc,exports,base,label):
    p,os,thread=setup(library,libc,base,label);seed,nos,nthread=setup(library,libc,base,label)
    assert thread==nthread
    actual=[];expected=[];remaining=list(nos.mappings);freed=set();nfreed=set();region_snapshots=[];native_region_snapshots=[];registration=[label=='register_then_exit']
    return_value=0x123456789abcdef0
    def mutation(r,w,label_event,argument):
        if label_event=='cxa' and label=='cxa_publish' and argument==GUEST+0x1200:
            w(CXA+32,CB0);w(CXA+40,GUEST+0x1210);w(CXA+48,0x77);w(CXA+56,r(HEAD));w(HEAD,CXA+32)
        if label_event=='cxa' and label=='cxa_clear':w(HEAD,0)
        if label_event=='cleanup' and label=='cleanup_publish' and argument==GUEST+0x1600:
            w(CLEANUP+24,r(thread+0x58));w(CLEANUP+32,CB1);w(CLEANUP+40,GUEST+0x1610);w(thread+0x58,CLEANUP+24)
        if label_event=='cleanup' and label=='cleanup_clear':w(thread+0x58,0)
    def ncallback(kind):
        def callback(cpu):
            argument=cpu.reg_read(UC_ARM64_REG_X0);expected.append([kind,argument])
            mutation(lambda a:read(cpu,a),lambda a,v:write(cpu,a,v),kind,argument);return 0
        return callback
    def invoke(pages,function,argument):
        if function in (CB0,CB1):
            kind='cxa' if function==CB0 else 'cleanup';actual.append([kind,argument])
            mutation(lambda a:get(pages,a),lambda a,v:put(pages,a,v),kind,argument)
        else:startup.invoke_registered_thread_destructor(pages,function_address=function,
            object_address=argument,image_base=base,free=free)
    def width(pointer):
        if CXA<=pointer<CXA+0x80:return 32
        return {NODE:40,GUEST+0x2600:32,GUEST+0x3000:8,GUEST+0x3100:48,GUEST+0x3200:16,GUEST+0x3500:24}[pointer]
    def nfree(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);assert pointer not in nfreed;nfreed.add(pointer)
        expected.append(['free',pointer]);cpu.mem_write(pointer,bytes([0xd7])*width(pointer));return 0
    def free(pages,pointer):
        assert pointer not in freed;freed.add(pointer);actual.append(['free',pointer])
        allocator._write_span(pages,pointer,bytes([0xd7])*width(pointer))
    def nget(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0)==root.LIBC_BASE+0xdb3a8
        expected.append(['get_libc_tls']);return HEAD
    def get_tls(pages,descriptor):
        assert descriptor==root.LIBC_BASE+0xdb3a8;actual.append(['get_libc_tls']);return HEAD
    def nimage_tls(cpu):
        descriptor=cpu.reg_read(UC_ARM64_REG_X0)
        return {base+0x3d13c0:FHEAD,base+0x3d13a0:FLAG}[descriptor]
    def image_tls(pages,descriptor):return {base+0x3d13c0:FHEAD,base+0x3d13a0:FLAG}[descriptor]
    def nset(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_setspecific'])
    def set_specific(pages,k,value):return allocator.pthread_setspecific(pages,key=k,value=value,
        thread_pointer=WORKER_TLS,generation_table=TABLE)
    def outcome(operation,fields):
        if label=='alt_os_failure' and operation in ('sigaltstack','munmap'):return -22 if operation=='sigaltstack' else -5
        if label=='main_os_failure' and operation in ('set_tid_address','munmap'):return -22
        return 0
    def os_call(pages,operation,*fields):
        actual.append([operation,*fields]);result=outcome(operation,fields)
        if operation=='munmap':
            region_snapshots.append((fields,allocator._read_span(pages,fields[0],fields[1])))
        if result<0 and (operation=='sigaltstack' or operation=='set_tid_address' or operation=='munmap' and label=='alt_os_failure'):
            put(pages,WORKER_TLS+0x10,-result,4)
        return result
    def syscall(cpu,number):
        fields=[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
        if number==132:
            assert fields[1]==0
            assert read(cpu,fields[0])==0 and read(cpu,fields[0]+8,4)==2
            operation='sigaltstack';values=[0,2]
        elif number==215:operation='munmap';values=fields[:2]
        elif number==96:operation='set_tid_address';values=fields[:1]
        elif number==135:
            assert fields[2]!=0 and fields[3]==8
            operation='sigprocmask';values=[fields[0],read(cpu,fields[1]),0,fields[3]]
        elif number==93:
            operation='exit';values=fields[:1];cpu.reg_write(UC_ARM64_REG_PC,STOP)
        else:raise allocator.RefillUnsupported(f'unknown exit syscall {number}')
        expected.append([operation,*values]);result=outcome(operation,values)
        if operation=='munmap':native_region_snapshots.append((tuple(values),bytes(cpu.mem_read(*values))))
        if operation=='munmap' and result>=0:
            mapping=next(item for item in remaining if [item.base,item.length]==values)
            cpu.mem_unmap(mapping.base,mapping.length);remaining.remove(mapping)
        return result
    # Only controlled entry fields overwrite libc inputs; imports remain linked
    # from the actual ELF's symbols and relocation table by native().
    entry=root.LIBC_BASE+0x68138 if not registration[0] else root.LIBC_BASE+0x6b23c
    entry_seen=[False];registered=[False]
    def observe(cpu,address):
        if address==entry and not entry_seen[0]:
            entry_seen[0]=True
            for a,n in ((TABLE,141*16),(root.LIBC_BASE+0xe01d0,4),(root.LIBC_BASE+0xe01f8,8)):
                cpu.mem_write(a,allocator._read_span(seed,a,n))
            for item in nos.mappings:
                cpu.mem_map(item.base,item.length);cpu.mem_write(item.base,allocator._read_span(seed,item.base,item.length))
    def allocate_native(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0)==32;expected.append(['allocate',32,CXA]);return CXA
    def allocate(pages,size):assert size==32;actual.append(['allocate',32,CXA]);return CXA
    def continuation(cpu):
        assert not registered[0];registered[0]=True
        cpu.reg_write(UC_ARM64_REG_X0,return_value);cpu.reg_write(UC_ARM64_REG_X30,STOP)
        cpu.reg_write(UC_ARM64_REG_PC,root.LIBC_BASE+0x68138);return None
    ranges={(WORKER_TLS,0xc00):None,(TABLE,141*16):None,
        (root.LIBC_BASE+0xe01d0,4):None,(root.LIBC_BASE+0xe01f8,8):None}
    ranges.update({(k<<12,4096):None for k in p if base<=k<<12<base+0x400000})
    args=[return_value] if not registration[0] else [base+0x268cf0,TREE,0x55]
    if registration[0]:
        for pages in (p,seed):put(pages,TREE+8,NODE);put(pages,NODE,0);put(pages,NODE+8,0)
    oracle=inputs(seed)
    for mapping in nos.mappings:
        for k in range(mapping.base>>12,mapping.end>>12):oracle.pop(k)
    hooks={root.LIBC_BASE+0x9be24-base:nget,root.LIBC_BASE+0x2871c-base:nfree,
        root.LIBC_BASE+0x286e8-base:allocate_native,0x347fa0:nfree,0x34377c:nimage_tls,
        0x348580:nset,CB0-base:ncallback('cxa'),CB1-base:ncallback('cleanup'),CONTINUE-base:continuation}
    _,memory,_,_=native(library,base,entry-base,args,oracle,libc=libc,real_mutexes=True,
        host_imports=hooks,instruction_observer=observe,syscall_handler=syscall,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:WORKER_TLS,
            UC_ARM64_REG_X30:CONTINUE if registration[0] else STOP},observed_memory=ranges,instruction_limit=60000)
    if registration[0]:exit_model.register_libc_thread_destructor(p,function_address=base+0x268cf0,
        object_address=TREE,dso_address=0x55,libc_base=root.LIBC_BASE,allocate=allocate,get_tls=get_tls)
    result=exit_model.run_pthread_exit(os,image_base=base,libc_base=root.LIBC_BASE,
        thread_pointer=WORKER_TLS,return_value=return_value,get_libc_tls=get_tls,invoke=invoke,
        free=free,os_call=os_call,set_specific=set_specific,get_image_tls=image_tls)
    assert actual==expected,('exit ordered effects',label,actual,expected)
    assert allocator._read_span(p,GUEST,0xa000)==memory,('exit guest',label)
    assert all(allocator._read_span(p,a,n)==v for (a,n),v in ranges.items()),('exit TLS/list/key',label)
    assert os.mappings==remaining,('owned guest mapping lifetime',label)
    assert region_snapshots==native_region_snapshots,('thread/region before release',label)
    assert not result.host_thread_terminated and entry_seen[0]
    assert all(k not in p for mapping in nos.mappings if mapping not in remaining
        for k in range(mapping.base>>12,mapping.end>>12))
    return dict(case=label,image_base=hex(base),actual_pthread_exit_body=True,
        guest_tls_key_list_match=True,ordered_effects_match=True,
        libc_callback_count=result.libc_destructors,cleanup_callback_count=result.cleanup_handlers,
        detached=result.detached,thread_unlinked=result.unlinked,unmapped_owned_regions=result.unmapped_regions,
        actual_registered_tree_destructor=label in ('cxa_real_tree','cleanup_real_tree','mixed_keys','register_then_exit'),
        native_libc_registration_and_exit_composed=registration[0],mixed_image_key_destructors=label=='mixed_keys',
        actual_executor_callback_from_fallback=label=='fallback_executor',
        actual_constructor_used_for_executor_exit_fixture=False,main_image_pages_match=True,
        guest_os_mappings_match=True,live_region_bytes_before_munmap_match=True,explicit_allocator_tls_os_and_synthetic_callback_controls=True,
        native_input_snapshot_used=False,complete_real_os_exit=False,real_allocator_boot=False)


def rejection_cases(library,libc):
    results=[]
    for label in ('unknown_shared_vtable','unknown_payload_vtable','missing_join','join_fails',
            'unknown_cxa_callback','cxa_cycle_bound','cleanup_cycle_bound','list_mutex_contended',
            'missing_owned_region','partial_unmap','os_call_invalid_result'):
        base=0x122c0000;p,os,thread=setup(library,libc,base,'detached_region' if label=='missing_owned_region' else 'detached')
        events=[]
        owner=GUEST+0x2600;payload=GUEST+0x2700
        put(p,owner,base+0x372670);put(p,owner+8,0);put(p,owner+16,0);put(p,owner+24,payload)
        put(p,payload,base+0x372648);put(p,payload+16,0)
        if label=='unknown_shared_vtable':put(p,owner,0)
        if label=='unknown_payload_vtable':put(p,payload,0)
        if label in ('missing_join','join_fails'):put(p,payload+16,1)
        if label=='unknown_cxa_callback':put(p,HEAD,CXA);put(p,CXA,CB0);put(p,CXA+8,0);put(p,CXA+24,0)
        if label=='cxa_cycle_bound':put(p,HEAD,CXA);put(p,CXA,CB0);put(p,CXA+8,0);put(p,CXA+24,CXA)
        if label=='cleanup_cycle_bound':put(p,thread+0x58,CLEANUP);put(p,CLEANUP,CLEANUP);put(p,CLEANUP+8,CB0);put(p,CLEANUP+16,0)
        if label=='list_mutex_contended':put(p,root.LIBC_BASE+0xe01d0,2,2)
        if label=='missing_owned_region':os.mappings=[]
        if label=='partial_unmap':mapping=os.map_anonymous(0x6000);put(p,thread+0x20,mapping.base);put(p,thread+0xa8,0x5000)
        original={k:bytes(v) for k,v in p.items()};mappings=list(os.mappings)
        def invoke(pages,function,arg):
            events.append('callback')
            if label=='unknown_cxa_callback':raise allocator.RefillUnsupported('unknown callback')
        def free(pages,pointer):events.append('free')
        def os_call(pages,operation,*args):events.append(operation);return None if label=='os_call_invalid_result' else 0
        try:
            if label in ('unknown_shared_vtable','unknown_payload_vtable','missing_join','join_fails'):
                startup.release_executor_shared(p,owner_address=owner,image_base=base,free=free,
                    join_thread=(lambda *args:22) if label=='join_fails' else None)
            else:exit_model.run_pthread_exit(os,image_base=base,libc_base=root.LIBC_BASE,
                thread_pointer=WORKER_TLS,return_value=7,get_libc_tls=lambda *args:HEAD,
                invoke=invoke,free=free,os_call=os_call,max_nodes=2)
        except allocator.RefillUnsupported:pass
        else:raise AssertionError(('expected explicit rejection',label))
        assert {k:bytes(v) for k,v in p.items()}==original and os.mappings==mappings,label
        results.append(dict(case=label,rejected=True,guest_pages_and_mappings_unchanged=True,
            external_effects=len(events),external_provider_effects_rolled_back=False))
    return results


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    with args.libc.open('rb') as f:
        elf=ELFFile(f);exports={s.name:root.LIBC_BASE+s['st_value'] for sec in elf.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    shared=[];exits=[]
    for base in (0x122c0000,0x775c205000):
        for label in ('old_shared_one','weak_zero','weak_one','weak_u64max','null_handle',
                'shared_only','registered_destructor','shared_u64max'):
            shared.append(shared_case(args.library,args.libc,base,label));print('shared',hex(base),label,'PASS',flush=True)
        for label in ('joinable','already_exited','already_joined','other_state','detached','head','middle','tail',
                'detached_region','detached_struct_in_region','joinable_region','altstack','alt_os_failure','main_os_failure',
                'cxa_one','cxa_three','cxa_publish','cxa_clear','cxa_real_tree','register_then_exit',
                'cleanup_one','cleanup_two','cleanup_publish','cleanup_clear','cleanup_real_tree','mixed_keys','fallback_executor'):
            exits.append(exit_case(args.library,args.libc,exports,base,label));print('exit',hex(base),label,'PASS',flush=True)
    report=dict(schema='vm9-guest-pthread-exit-v1',sample_sha256=LIBRARY_SHA256,
        libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),shared_cases=shared,exit_cases=exits,
        rejection_cases=rejection_cases(args.library,args.libc),native_input_snapshot_used=False,
        complete_real_os_exit=False,real_allocator_boot=False,standalone_medusa_complete=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(shared=len(shared),pthread_exit=len(exits),rejected=len(report['rejection_cases']))))


if __name__=='__main__':main()
