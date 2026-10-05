"""Fresh matching-libc key cleanup and bounded empty support destruction.

Synthetic callback behavior is an explicit control input. Returned native
memory is compared as output only; no native snapshot seeds the Python model.
This does not execute the rest of pthread_exit or emulated-TLS destruction.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_startup as startup
import verify_vm9_root_configuration as root
from verify_vm9_startup_worker_loop import inputs,put,get,WORKER_TLS
from verify_vm9_signer_objects import native,GUEST,LIBRARY_SHA256

TABLE=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET
KEY_CLEANUP_OFFSET=0x685a0
CALLBACKS=(GUEST+0xf200,GUEST+0xf210)


def fresh(library,libc,base):
    p=inputs(library,libc,base,137)
    allocator._write_span(p,TABLE,bytes(141*16))
    return p


def slot(p,index):return get(p,WORKER_TLS+8)+0xe8+index*16


def key(p,index,generation=1,saved=1,value=None,destructor=None):
    if value is None:value=GUEST+0x1000+index*16
    if destructor is None:destructor=CALLBACKS[index%2]
    put(p,TABLE+index*16,generation);put(p,TABLE+index*16+8,destructor)
    put(p,slot(p,index),saved);put(p,slot(p,index)+8,value)


def key_case(library,libc,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    for pages in (p,seed):
        if label=='inactive_value':key(pages,2,generation=2,saved=2)
        elif label=='stale_value':key(pages,2,generation=3,saved=1)
        elif label=='null_destructor':key(pages,2,destructor=0)
        elif label=='null_value':key(pages,2,value=0)
        elif label=='ordered_keys':
            for index in (140,3,2):key(pages,index)
        elif label=='publish_later_key':key(pages,2);key(pages,140,value=0)
        elif label=='delete_later_key':key(pages,2);key(pages,140)
        elif label!='empty':key(pages,2)
    native_calls=[];model_calls=[]
    def action(read,write,index,count):
        if label=='republish_four_passes':
            write(slot(p,index),read(TABLE+index*16));write(slot(p,index)+8,GUEST+0x1000+index*16)
        if label=='publish_later_key' and index==2:
            write(slot(p,140),read(TABLE+140*16));write(slot(p,140)+8,GUEST+0x1000+140*16)
        if label=='delete_later_key' and index==2:write(TABLE+140*16,2)
    def callback(cpu):
        value=cpu.reg_read(UC_ARM64_REG_X0);index=(value-GUEST-0x1000)//16
        read=lambda a:int.from_bytes(cpu.mem_read(a,8),'little')
        write=lambda a,v:cpu.mem_write(a,v.to_bytes(8,'little'))
        assert read(slot(seed,index)+8)==0,'native clears before destructor'
        native_calls.append(index);action(read,write,index,len(native_calls));return 0
    entry=root.LIBC_BASE+KEY_CLEANUP_OFFSET
    def observe(cpu,address):
        if address==entry:cpu.mem_write(TABLE,allocator._read_span(seed,TABLE,141*16))
    oracle={k:v for k,v in seed.items() if not root.LIBC_BASE<=k<<12<root.LIBC_BASE+0x400000}
    observed={(WORKER_TLS,0xc00):None,(TABLE,141*16):None}
    native(library,base,entry-base,[],oracle,libc=libc,real_mutexes=True,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:WORKER_TLS},instruction_observer=observe,
        host_imports={address-base:callback for address in CALLBACKS},
        observed_memory=observed,instruction_limit=100000)
    def invoke(pages,function,value):
        assert function in CALLBACKS
        index=(value-GUEST-0x1000)//16
        assert get(pages,slot(pages,index)+8)==0,'model clears before destructor'
        model_calls.append(index)
        action(lambda a:get(pages,a),lambda a,v:put(pages,a,v),index,len(model_calls))
    calls=allocator.pthread_key_clean_all(p,thread_pointer=WORKER_TLS,
        generation_table=TABLE,invoke=invoke)
    expected={'empty':[],'inactive_value':[],'stale_value':[],'null_destructor':[],
        'null_value':[],'ordered_keys':[2,3,140],'publish_later_key':[2,140],
        'delete_later_key':[2],'republish_four_passes':[2]*4,'one_key':[2]}[label]
    assert model_calls==native_calls==expected,label
    assert len(calls)==len(expected),label
    assert all(allocator._read_span(p,address,width)==data for (address,width),data in observed.items()),label
    if label=='republish_four_passes':assert get(p,slot(p,2)+8)!=0
    if label in ('inactive_value','stale_value'):assert get(p,slot(p,2)+8)!=0
    return dict(image_base=hex(base),case=label,destructor_calls=len(calls),
        key_order_match=True,complete_tls_generation_state_match=True,
        value_cleared_before_callback=True,four_pass_bound_verified=label=='republish_four_passes',
        inactive_stale_values_retained=label in ('inactive_value','stale_value'),
        synthetic_destructor_provider=True,native_input_snapshot_used=False)


def support_case(library,libc,base,label):
    p=fresh(library,libc,base);seed=fresh(library,libc,base)
    wrapper=0 if label=='null_wrapper' else GUEST+0x1000
    support=0 if label in ('null_wrapper','null_support') else GUEST+0x2000
    storage=GUEST+0x3000;conditions=GUEST+0x3800
    for pages in (p,seed):
        if wrapper:put(pages,wrapper,support)
        if support:
            allocator._write_span(pages,support,bytes(48))
            if label=='reserved_empty_vectors':
                for i,value in enumerate((storage,storage,storage+32,conditions,conditions,conditions+64)):
                    put(pages,support+i*8,value)
    frees=[]
    def free(cpu):frees.append(cpu.reg_read(UC_ARM64_REG_X0));return 0
    oracle={k:v for k,v in seed.items() if not root.LIBC_BASE<=k<<12<root.LIBC_BASE+0x400000}
    _,memory,_,_=native(library,base,0x32ce6c,[wrapper],oracle,libc=libc,
        host_imports={0x347fa0:free},instruction_limit=10000)
    actual=[]
    startup.destroy_empty_worker_support(p,wrapper_address=wrapper,free=lambda p,a:actual.append(a))
    expected=[] if label=='null_wrapper' else [wrapper] if label=='null_support' else (
        [conditions,storage,support,wrapper] if label=='reserved_empty_vectors' else [support,wrapper])
    assert actual==frees==expected,label
    assert allocator._read_span(p,GUEST,0xa000)==memory,label
    return dict(image_base=hex(base),case=label,free_calls=len(frees),guest_state_match=True,
        support_and_wrapper_free_order_match=True,empty_vectors_only=True,native_input_snapshot_used=False)


def negatives(library,libc):
    base=0x122c0000;cases=[]
    for label in ('unknown_exit_destructor','callback_failure','nonempty_support_vector'):
        p=fresh(library,libc,base);effects=[];wrapper=GUEST+0x1000;support=GUEST+0x2000
        if label=='nonempty_support_vector':
            put(p,wrapper,support);allocator._write_span(p,support,bytes(48))
            for i,value in enumerate((GUEST+0x3000,GUEST+0x3008,GUEST+0x3008)):
                put(p,support+i*8,value)
            key(p,2,value=wrapper,destructor=base+0x32ce6c)
        else:key(p,2)
        before={k:bytes(v) for k,v in p.items()}
        def reject(*args):effects.append('callback');raise allocator.RefillUnsupported('synthetic callback fails')
        try:
            if label=='callback_failure':allocator.pthread_key_clean_all(p,
                thread_pointer=WORKER_TLS,generation_table=TABLE,invoke=reject)
            else:startup.run_worker_thread_key_cleanup(p,image_base=base,thread_pointer=WORKER_TLS,
                generation_table=TABLE,free=lambda *a:effects.append('free'))
        except allocator.RefillUnsupported:pass
        else:raise AssertionError(label+' accepted')
        assert {k:bytes(v) for k,v in p.items()}==before,label
        assert 'free' not in effects,label
        cases.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            no_free_on_unsupported_exit=True,external_effects_rolled_back=False))
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    labels=('empty','inactive_value','stale_value','null_destructor','null_value','one_key',
        'ordered_keys','republish_four_passes','publish_later_key','delete_later_key')
    keys=[key_case(args.library,args.libc,base,label) for base in (0x122c0000,0x775c205000) for label in labels]
    support=[support_case(args.library,args.libc,base,label) for base in (0x122c0000,0x775c205000)
        for label in ('null_wrapper','null_support','empty_support','reserved_empty_vectors')]
    rejected=negatives(args.library,args.libc)
    report=dict(library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        key_cleanup_native_runs=len(keys),support_destructor_native_runs=len(support),
        key_cleanup_cases=keys,support_destructor_cases=support,negative_cases=rejected,
        pthread_key_cleanup_phase_verified=True,empty_support_destructor_verified=True,
        same_startup_worker_exit_key_phase_verified=False,emulated_tls_destructor_executed=False,
        complete_os_thread_exit=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(key_cleanup_native_runs=len(keys),support_native_runs=len(support),negative_checks=len(rejected))))


if __name__=='__main__':main()
