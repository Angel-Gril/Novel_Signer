"""Fresh native emulated/fallback TLS and nonempty support exit controls.

Callback, allocator poisoning and scheduling inputs are explicit synthetic
services. Native outputs are expectations only. This does not run pthread_exit,
real allocator shutdown or other concrete shared/fallback destructors.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
    UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0)
import vm9_allocator as allocator
import vm9_objects as objects
import vm9_startup as startup
import verify_vm9_root_configuration as root
from verify_vm9_thread_key_cleanup import fresh,slot,key,TABLE,WORKER_TLS
from verify_vm9_startup_worker_loop import put,get
from verify_vm9_signer_objects import native,GUEST,STOP,LIBRARY_SHA256
from verify_vm9_strings import Effects

CALLBACK=GUEST+0xf200
CONTINUE=GUEST+0xf400


def native_inputs(seed):
    return {k:v for k,v in seed.items() if not root.LIBC_BASE<=k<<12<root.LIBC_BASE+0x400000}


def observed(p,base):
    result={(WORKER_TLS,0xc00):None,(TABLE,141*16):None}
    result.update({(k<<12,4096):None for k in p if base<=k<<12<base+0x400000})
    return result


def compare(p,memory,state,label):
    assert allocator._read_span(p,GUEST,0xa000)==memory,('guest',label)
    assert all(allocator._read_span(p,a,n)==v for (a,n),v in state.items()),('image/TLS/generation',label)


def read(cpu,a,n=8):return int.from_bytes(cpu.mem_read(a,n),'little')
def write(cpu,a,v,n=8):cpu.mem_write(a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def array_case(library,libc,exports,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    array=GUEST+0x2000;first=GUEST+0x3000;second=GUEST+0x3100
    for pages in (p,seed):
        key(pages,2,value=0,destructor=base+0x3439bc)
        put(pages,base+0x3e31f4,0x80000002,4)
        delay={'defer_one':1,'defer_u64':(1<<64)-1,'defer_set_failure':1}.get(label,0)
        put(pages,array,delay);put(pages,array+8,0 if label=='empty' else 1 if label=='grow_after_free' else 3)
        for index,value in enumerate((first+16,0,second+16)):put(pages,array+16+index*8,value)
        put(pages,first+8,first);put(pages,second+8,second)
    expected=[];actual=[]
    def native_free(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);expected.append(['free',pointer])
        if pointer==first and label in ('shrink_after_free','grow_after_free'):
            write(cpu,array+8,1 if label=='shrink_after_free' else 3)
        cpu.mem_write(pointer,bytes([0xd7])*(40 if pointer==array else 32));return 0
    def model_free(pages,pointer):
        actual.append(['free',pointer])
        if pointer==first and label in ('shrink_after_free','grow_after_free'):
            put(pages,array+8,1 if label=='shrink_after_free' else 3)
        allocator._write_span(pages,pointer,bytes([0xd7])*(40 if pointer==array else 32))
    def native_set(cpu):
        expected.append(['set',cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1)])
        if label=='defer_set_failure':return 22
        cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_setspecific'])
    def model_set(pages,k,value):
        actual.append(['set',k,value])
        if label=='defer_set_failure':return 22
        return allocator.pthread_setspecific(pages,key=k,value=value,thread_pointer=WORKER_TLS,generation_table=TABLE)
    def observe(cpu,address):
        if address==base+0x3439bc:cpu.mem_write(TABLE,allocator._read_span(seed,TABLE,141*16))
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x3439bc,[array],native_inputs(seed),libc=libc,real_mutexes=True,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:WORKER_TLS},instruction_observer=observe,
        host_imports={0x347fa0:native_free,0x348580:native_set},observed_memory=state,instruction_limit=100000)
    freed=objects.destroy_emulated_tls_array(p,array_address=array,image_base=base,
        free=model_free,set_specific=model_set)
    assert actual==expected,label
    assert freed==(not label.startswith('defer')),label
    compare(p,memory,state,label)
    return dict(image_base=hex(base),case=label,free_calls=sum(e[0]=='free' for e in actual),
        deferral_branch_taken=not freed,guest_image_tls_generation_match=True,ordered_effects_match=True,
        allocator_poisoning_is_explicit=True,native_input_snapshot_used=False)


def fallback_case(library,libc,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    head=GUEST+0x1800;other=GUEST+0x1810;flag=GUEST+0x1820
    nodes=(GUEST+0x2000,GUEST+0x2020,GUEST+0x2040)
    for pages in (p,seed):
        put(pages,head,0 if label=='empty' else nodes[0]);put(pages,flag,3,1)
        for i,node in enumerate(nodes):
            put(pages,node,CALLBACK);put(pages,node+8,i+1)
            put(pages,node+16,nodes[i+1] if i<1 and label!='one' else 0)
        if label=='three':put(pages,nodes[1]+16,nodes[2])
    expected=[];actual=[];native_get=[0];model_get=[0]
    def resolve(events,count,control):
        offset=control-base;events.append(['tls',offset])
        if offset==0x3d13a0:return flag
        assert offset==0x3d13c0;count[0]+=1
        return other if label=='relocated_head' and count[0]>1 else head
    def ntls(cpu):return resolve(expected,native_get,cpu.reg_read(UC_ARM64_REG_X0))
    def ptls(pages,control):return resolve(actual,model_get,control)
    def callback_effect(events,load,store,argument):
        target=other if label=='relocated_head' else head
        assert load(target)!=nodes[argument-1],'head popped before callback'
        events.append(['callback',argument])
        if argument==1 and label=='publish_node':
            store(nodes[2]+16,load(target));store(target,nodes[2])
        if argument==1 and label=='clear_head':store(target,0)
    def ncallback(cpu):callback_effect(expected,lambda a:read(cpu,a),lambda a,v:write(cpu,a,v),cpu.reg_read(UC_ARM64_REG_X0));return 0
    def pcallback(pages,function,argument):
        assert function==CALLBACK
        callback_effect(actual,lambda a:get(pages,a),lambda a,v:put(pages,a,v),argument)
    def nfree(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);expected.append(['free',pointer]);cpu.mem_write(pointer,bytes([0xd7])*24);return 0
    def pfree(pages,pointer):actual.append(['free',pointer]);allocator._write_span(pages,pointer,bytes([0xd7])*24)
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x342854,[0],native_inputs(seed),libc=libc,
        host_imports={0x34377c:ntls,0x347fa0:nfree,CALLBACK-base:ncallback},
        observed_memory=state,instruction_limit=100000)
    count=objects.run_emulated_thread_destructors(p,image_base=base,get_tls=ptls,invoke=pcallback,free=pfree)
    assert actual==expected,label
    compare(p,memory,state,label)
    order=[e[1] for e in actual if e[0]=='callback']
    assert order=={'empty':[],'one':[1],'three':[1,2,3],'publish_node':[1,3,2],
        'clear_head':[1],'relocated_head':[1,2]}[label],label
    assert get(p,flag,1)==0
    return dict(image_base=hex(base),case=label,destructor_calls=count,head_removed_before_callback=True,
        callback_published_node_verified=label=='publish_node',final_flag_cleared=True,guest_image_tls_generation_match=True,
        ordered_effects_match=True,explicit_tls_getter_used=True,native_input_snapshot_used=False)


def support_case(library,libc,exports,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    wrapper=GUEST+0x1000;support=GUEST+0x2000;pairs=GUEST+0x3000;refs=GUEST+0x3200
    cond=GUEST+0x3800;mutex=GUEST+0x3820;obj=GUEST+0x4000;second=GUEST+0x4200;table=GUEST+0x1f00
    pair_count=0 if label.startswith('refs') else 2 if label=='two_pairs' else 1
    ref_count=0 if label in ('one_pair','two_pairs','shared_pair') else 2 if label=='refs_alias' else 1
    for pages in (p,seed):
        put(pages,wrapper,support);allocator._write_span(pages,support,bytes(48))
        if pair_count:
            for i,v in enumerate((pairs,pairs+pair_count*16,pairs+32)):put(pages,support+0x18+i*8,v)
            for i in range(pair_count):
                put(pages,pairs+i*16,cond+i*0x40);put(pages,pairs+i*16+8,mutex+i*0x40)
                put(pages,mutex+i*0x40,0x2001 if label=='shared_pair' else 1,2)
                put(pages,cond+i*0x40,1 if label=='shared_pair' else 0,4)
        if ref_count:
            for i,v in enumerate((refs,refs+ref_count*8,refs+16)):put(pages,support+i*8,v)
            for i in range(ref_count):put(pages,refs+i*8,obj)
            for address in (obj,second):
                allocator._write_span(pages,address,bytes(128));put(pages,address,table)
                put(pages,address+8,0 if label=='refs_zero' else 2)
                put(pages,address+0x70,0xfffffff8,4)
            put(pages,table+0x10,CALLBACK)
    expected=[];actual=[]
    def native_broadcast(cpu):
        address=cpu.reg_read(UC_ARM64_REG_X0)
        expected.append(['broadcast',address])
        if label=='refs_reload' and address==obj+0x40:write(cpu,refs,second)
        cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_broadcast'])
    def syscall(cpu,number):
        assert number==98
        expected.append(['wake',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]]);return 0
    def wake(pages,*args):actual.append(['wake',*args]);return 0
    def broadcast(pages,address):
        actual.append(['broadcast',address])
        if label=='refs_reload' and address==obj+0x40:put(pages,refs,second)
        return objects.broadcast_condition_no_waiters(pages,condition_address=address,wake=wake)
    def nzero(cpu):
        address=cpu.reg_read(UC_ARM64_REG_X0);assert read(cpu,address+8)==(1<<64)-1
        expected.append(['zero_shared',address]);write(cpu,address+0x78,0x53);return 0
    def pzero(pages,function,address):
        assert function==CALLBACK and get(pages,address+8)==(1<<64)-1
        actual.append(['zero_shared',address]);put(pages,address+0x78,0x53)
    def nfree(cpu):expected.append(['free',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def pfree(pages,address):actual.append(['free',address])
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x32ce6c,[wrapper],native_inputs(seed),libc=libc,real_mutexes=True,
        host_imports={0x3485a0:native_broadcast,0x347fa0:nfree,CALLBACK-base:nzero},
        syscall_handler=syscall,observed_memory=state,instruction_limit=100000)
    startup.destroy_worker_support(p,wrapper_address=wrapper,free=pfree,broadcast=broadcast,invoke_shared=pzero)
    assert actual==expected,('support events',label,actual,expected)
    compare(p,memory,state,label)
    return dict(image_base=hex(base),case=label,waiter_pairs=pair_count,reference_entries=ref_count,
        zero_shared_calls=sum(e[0]=='zero_shared' for e in actual),guest_image_tls_generation_match=True,
        ordered_unlock_broadcast_flag_count_and_free_match=True,
        shared_zero_callback_is_explicit=True,native_input_snapshot_used=False)


def composition(library,libc,exports,base,count,with_support=False):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    blocks={GUEST+0x1400:8,GUEST+0x1500:48} if with_support else {}
    if with_support:
        for pages in (p,seed):
            put(pages,GUEST+0x1400,GUEST+0x1500)
            allocator._write_span(pages,GUEST+0x1500,bytes(48))
            key(pages,0,destructor=base+0x32ce6c,value=GUEST+0x1400)
    expected=[];actual=[];expected_heap=Effects(blocks=blocks);actual_heap=Effects(blocks=blocks)
    entry=base+0x34265c;registered=[0];seeded=[False]
    def observe(cpu,address):
        if address==entry and not seeded[0]:
            seeded[0]=True;cpu.mem_write(TABLE,allocator._read_span(seed,TABLE,141*16))
    def redirect(name,record=True):
        def call(cpu):
            if record:expected.append([name])
            cpu.reg_write(UC_ARM64_REG_PC,exports[name])
        return call
    def step(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0)==0
        registered[0]+=1;expected.append(['registered',registered[0]])
        if registered[0]<count:
            cpu.reg_write(UC_ARM64_REG_X0,CALLBACK);cpu.reg_write(UC_ARM64_REG_X1,registered[0]+1)
            cpu.reg_write(UC_ARM64_REG_X2,base+0x34c700);cpu.reg_write(UC_ARM64_REG_X30,CONTINUE)
            cpu.reg_write(UC_ARM64_REG_PC,entry)
        else:
            expected.append(['key_cleanup_enter']);cpu.reg_write(UC_ARM64_REG_X30,STOP)
            cpu.reg_write(UC_ARM64_REG_PC,root.LIBC_BASE+0x685a0)
    def nalloc(cpu,size):
        value=expected_heap.native(cpu,'malloc',size);expected.append(['allocate',size,value]);return value
    def nfree(cpu):
        value=cpu.reg_read(UC_ARM64_REG_X0);expected.append(['free',value]);return expected_heap.native(cpu,'free',pointer=value)
    def ncallback(cpu):expected.append(['callback',cpu.reg_read(UC_ARM64_REG_X0)]);return 0
    def natexit(cpu):expected.append(['atexit']);return 0
    def syscall(cpu,number):
        assert number==98;expected.append(['wake',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]]);return 0
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x34265c,[CALLBACK,1,base+0x34c700],native_inputs(seed),libc=libc,
        real_mutexes=True,real_singletons=True,thread_id=137,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:WORKER_TLS,UC_ARM64_REG_X30:CONTINUE},
        instruction_observer=observe,malloc_handler=nalloc,syscall_handler=syscall,
        host_imports={CONTINUE-base:step,CALLBACK-base:ncallback,0x347fa0:nfree,0x347ea0:natexit,
            0x348620:redirect('pthread_key_create'),0x348580:redirect('pthread_setspecific'),
            0x3485d0:redirect('pthread_getspecific'),0x3486b0:redirect('pthread_once',False)},
        observed_memory=state,instruction_limit=300000)
    def allocate(pages,size):
        value=actual_heap.malloc(pages,size);actual.append(['allocate',size,value]);return value
    def free_block(pages,address):actual.append(['free',address]);actual_heap.free(pages,address)
    def wake(pages,*args):actual.append(['wake',*args]);return 0
    def create(pages,address,destructor):
        actual.append(['pthread_key_create'])
        return allocator.pthread_key_create(pages,key_address=address,destructor=destructor,generation_table=TABLE)
    def specific(pages,k,value):
        actual.append(['pthread_setspecific'])
        return allocator.pthread_setspecific(pages,key=k,value=value,thread_pointer=WORKER_TLS,generation_table=TABLE)
    def get_specific(pages,k):
        actual.append(['pthread_getspecific'])
        return allocator.pthread_getspecific(pages,key=k,thread_pointer=WORKER_TLS,generation_table=TABLE)
    def get_tls(pages,descriptor):
        return objects.get_emulated_tls_address(pages,control_address=descriptor,image_base=base,
            allocate=allocate,reallocate=actual_heap.realloc,get_specific=get_specific,set_specific=specific,
            create_key=create,once_wake=wake)
    for i in range(count):
        result=objects.register_emulated_thread_destructor(p,destructor_address=CALLBACK,object_address=i+1,
            image_base=base,allocate=allocate,get_tls=get_tls,create_key=create,set_specific=specific,
            register_atexit=lambda *a:actual.append(['atexit']),thread_id=137)
        assert result==0;actual.append(['registered',i+1])
    actual.append(['key_cleanup_enter'])
    calls=startup.run_worker_thread_key_cleanup(p,image_base=base,thread_pointer=WORKER_TLS,
        generation_table=TABLE,free=free_block,set_specific=specific,get_tls=get_tls,
        invoke_destructor=lambda pages,function,value:actual.append(['callback',value]))
    assert actual==expected,('composition events',base,count,actual,expected)
    compare(p,memory,state,('composition',count))
    assert actual_heap.calls==expected_heap.calls and actual_heap.blocks==expected_heap.blocks=={}
    assert [e[1] for e in actual if e[0]=='callback']==list(range(count,0,-1))
    assert len(calls)==(4 if with_support else 3)  # Optional support, fallback, array defer/free.
    return dict(image_base=hex(base),registered_destructors=count,callback_returns=count,
        key_destructor_calls=len(calls),same_fresh_registration_and_key_cleanup=True,
        support_fallback_and_array_keys_composed=with_support,
        registration_lifo_and_array_defer_then_free_match=True,all_allocator_blocks_freed=True,
        guest_image_tls_generation_match=True,ordered_effects_match=True,
        synthetic_destructor_callbacks=True,native_input_snapshot_used=False,
        complete_os_thread_exit=False,complete_allocator_boot=False,complete_python_medusa=False)


def tree_case(library,libc,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    tree=GUEST+0x1800;nodes=[GUEST+0x2000+i*0x40 for i in range(4)]
    for pages in (p,seed):
        put(pages,tree,nodes[1]);put(pages,tree+8,0 if label=='empty' else nodes[0]);put(pages,tree+16,3)
        for node in nodes:allocator._write_span(pages,node,bytes(48))
        if label in ('balanced','right_reload'):put(pages,nodes[0],nodes[1]);put(pages,nodes[0]+8,nodes[2])
        if label=='left_chain':put(pages,nodes[0],nodes[1]);put(pages,nodes[1],nodes[2])
    expected=[];actual=[]
    def nfree(cpu):
        value=cpu.reg_read(UC_ARM64_REG_X0);expected.append(value)
        if label=='right_reload' and value==nodes[1]:write(cpu,nodes[0]+8,nodes[3])
        cpu.mem_write(value,bytes([0xd7])*48);return 0
    def pfree(pages,value):
        actual.append(value)
        if label=='right_reload' and value==nodes[1]:put(pages,nodes[0]+8,nodes[3])
        allocator._write_span(pages,value,bytes([0xd7])*48)
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x268cf0,[tree],native_inputs(seed),libc=libc,
        host_imports={0x347fa0:nfree},observed_memory=state,instruction_limit=100000)
    count=objects.destroy_scoped_tls_tree(p,tree_address=tree,free=pfree)
    order={'empty':[],'one':[nodes[0]],'balanced':[nodes[1],nodes[2],nodes[0]],
        'left_chain':[nodes[2],nodes[1],nodes[0]],'right_reload':[nodes[1],nodes[3],nodes[0]]}[label]
    assert actual==expected==order and count==len(order)
    compare(p,memory,state,label)
    return dict(image_base=hex(base),case=label,node_free_calls=count,
        postorder_and_right_reload_match=True,tree_header_retained=True,
        guest_image_tls_generation_match=True,native_input_snapshot_used=False)


def registry_composition(library,libc,exports,base,node_count):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    expected=[];actual=[];nheap=Effects(blocks={});pheap=Effects(blocks={})
    phase=[0];seeded=[False];tree_calls=[]
    def observe(cpu,address):
        if address==base+0x269880 and not seeded[0]:
            seeded[0]=True;cpu.mem_write(TABLE,allocator._read_span(seed,TABLE,141*16))
        if address==base+0x268cf0:
            expected.append(['scoped_tree_destructor']);tree_calls.append(cpu.reg_read(UC_ARM64_REG_X0))
    def nalloc(cpu,size):
        pointer=nheap.native(cpu,'malloc',size);expected.append(['allocate',size,pointer]);return pointer
    def nfree(cpu):
        pointer=cpu.reg_read(UC_ARM64_REG_X0);expected.append(['free',pointer]);return nheap.native(cpu,'free',pointer=pointer)
    def structure(store,tree,nodes):
        if nodes:
            store(tree,nodes[1]);store(tree+8,nodes[0]);store(tree+16,3)
            store(nodes[0],nodes[1]);store(nodes[0]+8,nodes[2])
            for node in nodes[1:]:store(node,0);store(node+8,0)
    def step(cpu):
        if phase[0]==0:
            phase[0]=1;expected.append(['registry_initialized'])
            cpu.reg_write(UC_ARM64_REG_X0,base+0x382450)
            cpu.reg_write(UC_ARM64_REG_X30,CONTINUE);cpu.reg_write(UC_ARM64_REG_PC,base+0x34377c)
        else:
            assert phase[0]==1;phase[0]=2
            tree=cpu.reg_read(UC_ARM64_REG_X0);nodes=[nalloc(cpu,48) for _ in range(node_count)]
            structure(lambda a,v:write(cpu,a,v),tree,nodes)
            expected.append(['key_cleanup_enter']);cpu.reg_write(UC_ARM64_REG_X30,STOP)
            cpu.reg_write(UC_ARM64_REG_PC,root.LIBC_BASE+0x685a0)
    def redirect(name,record=True):
        def call(cpu):
            if record:expected.append([name])
            cpu.reg_write(UC_ARM64_REG_PC,exports[name])
        return call
    def syscall(cpu,number):
        assert number==98;expected.append(['wake',*[cpu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]]);return 0
    def natexit(cpu):expected.append(['atexit']);return 0
    state=observed(p,base)
    _,memory,_,_=native(library,base,0x269880,[],native_inputs(seed),libc=libc,real_singletons=True,
        real_mutexes=True,thread_id=137,instruction_observer=observe,malloc_handler=nalloc,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:WORKER_TLS,UC_ARM64_REG_X30:CONTINUE},
        host_imports={CONTINUE-base:step,0x347fa0:nfree,0x347ea0:natexit,
            0x348620:redirect('pthread_key_create'),0x348580:redirect('pthread_setspecific'),
            0x3485d0:redirect('pthread_getspecific'),0x3486b0:redirect('pthread_once',False)},
        syscall_handler=syscall,observed_memory=state,instruction_limit=300000)
    def allocate(pages,size):
        pointer=pheap.malloc(pages,size);actual.append(['allocate',size,pointer]);return pointer
    def free_block(pages,address):actual.append(['free',address]);pheap.free(pages,address)
    def wake(pages,*args):actual.append(['wake',*args]);return 0
    def create(pages,address,destructor):
        actual.append(['pthread_key_create']);return allocator.pthread_key_create(pages,
            key_address=address,destructor=destructor,generation_table=TABLE)
    def specific(pages,k,value):
        actual.append(['pthread_setspecific']);return allocator.pthread_setspecific(pages,
            key=k,value=value,thread_pointer=WORKER_TLS,generation_table=TABLE)
    def get_specific(pages,k):
        actual.append(['pthread_getspecific']);return allocator.pthread_getspecific(pages,
            key=k,thread_pointer=WORKER_TLS,generation_table=TABLE)
    def get_tls(pages,descriptor):
        return objects.get_emulated_tls_address(pages,control_address=descriptor,image_base=base,
            allocate=allocate,reallocate=pheap.realloc,get_specific=get_specific,set_specific=specific,
            create_key=create,once_wake=wake)
    def register(pages,function,obj,dso):
        assert dso==base+0x34c700
        return objects.register_emulated_thread_destructor(pages,destructor_address=function,
            object_address=obj,image_base=base,allocate=allocate,get_tls=get_tls,create_key=create,
            set_specific=specific,register_atexit=lambda *a:actual.append(['atexit']),thread_id=137)
    objects.initialize_scoped_tls_registry(p,image_base=base,get_tls=get_tls,register_destructor=register)
    actual.append(['registry_initialized']);tree=get_tls(p,base+0x382450)
    assert (get(p,base+0x3e31f4,4)&0x7fffffff)<(get(p,base+0x3e2fb0,4)&0x7fffffff)
    nodes=[allocate(p,48) for _ in range(node_count)]
    structure(lambda a,v:put(p,a,v),tree,nodes)
    actual.append(['key_cleanup_enter']);calls=[];original=objects.destroy_scoped_tls_tree
    def checked_tree(pages,**kwargs):
        actual.append(['scoped_tree_destructor']);calls.append(kwargs['tree_address']);return original(pages,**kwargs)
    objects.destroy_scoped_tls_tree=checked_tree
    try:
        exits=startup.run_worker_thread_key_cleanup(p,image_base=base,thread_pointer=WORKER_TLS,
            generation_table=TABLE,free=free_block,set_specific=specific,get_tls=get_tls)
    finally:objects.destroy_scoped_tls_tree=original
    assert calls==tree_calls==[tree]
    assert actual==expected,('registry events',base,node_count,actual,expected)
    compare(p,memory,state,('registry',node_count))
    assert nheap.calls==pheap.calls and nheap.blocks==pheap.blocks=={}
    assert len(exits)==3
    return dict(image_base=hex(base),tree_nodes=node_count,actual_registry_callback_executed=True,
        synthetic_destructor_callback_used=False,same_fresh_registry_registration_and_key_cleanup=True,
        emulated_tls_key_precedes_fallback_key=True,array_deferral_keeps_tls_alive_for_fallback=True,
        all_allocator_blocks_freed=True,guest_image_tls_generation_match=True,ordered_effects_match=True,
        tree_population_is_explicit_synthetic_input=True,native_input_snapshot_used=False,
        complete_os_thread_exit=False,complete_allocator_boot=False,complete_python_medusa=False)


def negatives(library,libc):
    base=0x122c0000;cases=[]
    labels=('array_bound','array_grows_past_bound','array_defer_without_set',
        'fallback_callback_fails','fallback_cycle_bound','waiter_mutex_not_held',
        'reference_mutex_contended','shared_zero_without_provider','broadcast_fails',
        'key_fallback_missing_services','key_array_missing_set','tree_cycle_bound',
        'key_fallback_unknown_callback')
    for label in labels:
        p=fresh(library,libc,base);events=[]
        array=GUEST+0x2000;wrapper=GUEST+0x1000;support=GUEST+0x2100
        head=GUEST+0x1800;flag=GUEST+0x1810;node=GUEST+0x2200
        pairs=GUEST+0x3000;refs=GUEST+0x3100;obj=GUEST+0x4000
        allocator._write_span(p,array,bytes(48))
        put(p,array+8,1);put(p,array+16,GUEST+0x5010);put(p,GUEST+0x5008,GUEST+0x5000)
        if label=='array_bound':put(p,array+8,4097)
        if label in ('array_defer_without_set','key_array_missing_set'):put(p,array,1)
        put(p,head,node);put(p,flag,1,1)
        put(p,node,CALLBACK);put(p,node+8,1);put(p,node+16,node if label=='fallback_cycle_bound' else 0)
        put(p,wrapper,support);allocator._write_span(p,support,bytes(48))
        if label=='waiter_mutex_not_held':
            for i,v in enumerate((pairs,pairs+16,pairs+16)):put(p,support+0x18+i*8,v)
            put(p,pairs,GUEST+0x3800);put(p,pairs+8,GUEST+0x3820);put(p,GUEST+0x3820,0,2)
        elif label in ('reference_mutex_contended','shared_zero_without_provider','broadcast_fails'):
            for i,v in enumerate((refs,refs+8,refs+8)):put(p,support+i*8,v)
            put(p,refs,obj);allocator._write_span(p,obj,bytes(128))
            put(p,obj+0x18,2 if label=='reference_mutex_contended' else 0,2)
            put(p,obj+8,0)
        if label=='key_fallback_missing_services':key(p,2,destructor=base+0x342854,value=base+0x3e2fb0)
        if label=='key_array_missing_set':key(p,2,destructor=base+0x3439bc,value=array)
        if label=='tree_cycle_bound':put(p,head+8,node);put(p,node,node)
        if label=='key_fallback_unknown_callback':key(p,2,destructor=base+0x342854,value=base+0x3e2fb0)
        before={k:bytes(v) for k,v in p.items()}
        def free(pages,address):
            events.append('free')
            if label=='array_grows_past_bound':put(pages,array+8,4097)
        def callback(*args):
            events.append('callback')
            if label=='fallback_callback_fails':raise allocator.RefillUnsupported('synthetic callback failure')
        def getter(pages,descriptor):return head if descriptor==base+0x3d13c0 else flag
        def broadcast(pages,address):
            events.append('broadcast')
            if label=='broadcast_fails':raise allocator.RefillUnsupported('synthetic broadcast failure')
            return 0
        try:
            if label.startswith('array_'):
                objects.destroy_emulated_tls_array(p,array_address=array,image_base=base,free=free)
            elif label.startswith('fallback_'):
                objects.run_emulated_thread_destructors(p,image_base=base,get_tls=getter,
                    invoke=callback,free=free,max_nodes=2)
            elif label=='tree_cycle_bound':
                objects.destroy_scoped_tls_tree(p,tree_address=head,free=free,max_nodes=2)
            elif label.startswith('key_'):
                startup.run_worker_thread_key_cleanup(p,image_base=base,thread_pointer=WORKER_TLS,
                    generation_table=TABLE,free=free,
                    get_tls=getter if label=='key_fallback_unknown_callback' else None)
            else:startup.destroy_worker_support(p,wrapper_address=wrapper,free=free,broadcast=broadcast)
        except allocator.RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert {k:bytes(v) for k,v in p.items()}==before,('rollback',label)
        if label in ('array_grows_past_bound',):assert events==['free']
        if label=='fallback_cycle_bound':assert events==['callback','free']*2
        if label in ('waiter_mutex_not_held','reference_mutex_contended','key_fallback_missing_services','key_array_missing_set'):assert not events
        cases.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            external_provider_effects=len(events),external_effects_rolled_back=False))
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    with args.libc.open('rb') as f:
        elf=ELFFile(f);exports={sym.name:root.LIBC_BASE+sym['st_value'] for sec in elf.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for sym in sec.iter_symbols() if sym['st_shndx']!='SHN_UNDEF'}
    arrays=[];fallback=[];support=[];composed=[];trees=[];registries=[]
    for base in (0x122c0000,0x775c205000):
        arrays.extend(array_case(args.library,args.libc,exports,base,label) for label in
            ('empty','populated','defer_one','defer_u64','defer_set_failure','shrink_after_free','grow_after_free'))
        fallback.extend(fallback_case(args.library,args.libc,base,label) for label in
            ('empty','one','three','publish_node','clear_head','relocated_head'))
        support.extend(support_case(args.library,args.libc,exports,base,label) for label in
            ('one_pair','two_pairs','shared_pair','refs_positive','refs_zero','refs_alias','refs_reload','mixed'))
        composed.extend(composition(args.library,args.libc,exports,base,count) for count in (1,3))
        composed.append(composition(args.library,args.libc,exports,base,3,True))
        trees.extend(tree_case(args.library,args.libc,base,label) for label in ('empty','one','balanced','left_chain','right_reload'))
        registries.extend(registry_composition(args.library,args.libc,exports,base,count) for count in (0,3))
    rejected=negatives(args.library,args.libc)
    report=dict(negative_cases=rejected,library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        array_native_runs=len(arrays),fallback_native_runs=len(fallback),support_native_runs=len(support),
        composition_native_runs=len(composed),tree_native_runs=len(trees),registry_native_runs=len(registries),
        tree_cases=trees,registry_cases=registries,array_cases=arrays,fallback_cases=fallback,support_cases=support,
        composition_cases=composed,native_input_snapshot_used=False,
        complete_os_thread_exit=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(negative_checks=len(rejected),**{k:report[k] for k in ('array_native_runs','fallback_native_runs','support_native_runs','composition_native_runs','tree_native_runs','registry_native_runs')})))


if __name__=='__main__':main()
