"""Actual delayed bytecode and callable entries with explicit live JNI services.

Native evaluator and Python start from independently prepared fresh ELF inputs.
The registry is constructed by its existing owner; Android services are finite
synthetic providers. No native output or captured pages initialize Python.
"""
from pathlib import Path
import argparse,copy,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_live_initializer_fresh_20261012 as h
import vm9_jni_followup as model
import vm9_registry as registry
import vm9_objects as objects
import vm9_startup as startup
import vm9_worker_scheduler as scheduler
from vm9_allocator import _read_span,_write_span,_PageTransaction,RefillUnsupported

G=h.G;REG=G+0x8000;FLAG=G+0x8200;TREE=G+0x8300;REF=G+0x8500;COUNT=G+0x8510;CALLABLE=G+0x8600


class Services(h.Services):
    def read_clock(self,p,kind):return (0,123,456)
    def initialize_registry(self,p):
        objects.initialize_scoped_tls_registry(p,image_base=self.base,get_tls=self.vm.tls,register_destructor=self.vm.register)
    def broadcast(self,p,ptr):
        return objects.broadcast_condition_no_waiters(p,condition_address=ptr,wake=lambda *a:0)
    def imports(self):
        imports=super().imports()
        with self.libc.open('rb') as stream:
            elf=ELFFile(stream)
            address=next(0x51000000+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='pthread_cond_broadcast')
        def broadcast(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,address)
        imports[0x3485A0]=broadcast
        return imports
    def options(self,vm_module):
        return dict(thread_pointer=h.live.TP,thread_id=137,allocate=self.malloc,free=self.free,get_tls=self.vm.tls,
            initialize_registry=self.initialize_registry,broadcast=self.broadcast,register_destructor=self.vm.register,
            invoke_javavm=self.vm.model_vm,read_property=lambda *a:None,system=lambda *a:-2,vm_module=vm_module,
            invoke_jni=self.model_jni,calloc=self.calloc,reallocate=self.effects.realloc,
            diagnostic_observer=self.diagnostic,find_sdk_property=self.find_sdk,read_sdk_property=self.read_sdk)


def fresh(library,libc,base,sdk):
    p,blocks=h.fresh(library,base,sdk,dict(cold_sdk=True))
    seed=Services(base,sdk,blocks,dict(cold_sdk=True));seed.libc=libc
    model.w(p,h.CONFIG+0x80,h.live.RECEIVER);model.w(p,h.WRAPPER+8,COUNT);model.w(p,COUNT,1,4)
    for index,(control,target) in enumerate(((0x382470,FLAG),(0x382450,TREE)),5):
        model.w(p,base+control+16,index);model.w(p,h.live.acquisition.ARRAY+16+(index-1)*8,target)
    model.w(p,FLAG,1,1);model.w(p,TREE,TREE+8);model.w(p,TREE+8,0);model.w(p,TREE+16,0)
    registry.construct_registry320(p,object_address=REG,entry_stack_address=h.live.SP,image_base=base,
        allocate=seed.malloc,free=seed.free,read_clock=seed.read_clock,get_tls=seed.vm.tls,
        initialize_registry=seed.initialize_registry,broadcast=seed.broadcast)
    model.w(p,base+0x3D1550,REF);model.w(p,base+0x3D1558,0x101)
    model.w(p,REF,REG);model.w(p,REF+8,COUNT+8);model.w(p,COUNT+8,1,4)
    model.w(p,CALLABLE,base+0x34F058);model.w(p,CALLABLE+0x20,CALLABLE)
    return p,seed


def services(seed):
    result=Services(seed.base,seed.sdk,seed.effects.blocks,dict(cold_sdk=True));result.libc=seed.libc
    result.effects=copy.deepcopy(seed.effects);result.vm.effects=result.effects
    result.events=[];result.vm.events=result.events;result.freed=[]
    return result


def native_setup(p,base,sp):
    frame=sp-0x560;top=frame+0x530
    for address,value in ((frame+8,h.CONFIG),(frame+0x10,base+0x2043D4),
                          (frame+0x18,top),(frame+0x20,base+0x203B70)):
        model.w(p,address,value)
    return frame,top


def run_vm(p,service,vm_module,**changes):
    options=dict(base=service.base,sp=h.live.SP,payload=h.CONFIG,entry=0x89650,max_steps=10000,**service.options(vm_module))
    options.update(changes)
    staged=_PageTransaction(p);result=model._run_vm(staged,**options);staged.commit();return result


def run_callable(p,service,vm_module,**changes):
    options=dict(callable_address=CALLABLE,image_base=service.base,entry_stack_address=h.live.SP,
        read_clock=service.read_clock,**service.options(vm_module))
    options.update(changes);return model.run_delayed_followup_callable(p,**options)


def published_configuration_value(p,base):
    query=G+0x8800;source=base+0x3D9E10;length=0;staged=_PageTransaction(p)
    while _read_span(p,source+length,1)!=b'\0':
        length+=1;assert length<0x1000
    model.w(staged,query,base+0x34F5F8);model.w(staged,query+8,length+1,4)
    model.w(staged,query+12,length,4);model.w(staged,query+16,source)
    value=registry.lookup_configuration_value(staged,container_address=REG+8,key_address=query,image_base=base)
    return model.u(p,value,4) if value else None


def worker_boundary(p,service,vm_module,*,missing_calloc=False):
    base=service.base;queue=G+0x8900;threads=[]
    def create(staged,slot,attributes,entry,argument):
        handle=G+0x8E00;model.w(staged,slot,handle);threads.append((handle,entry,argument));return 0
    argument=startup.construct_async_queue(p,object_address=queue,scratch_address=G+0x8F00,
        image_base=base,allocate=service.malloc,create_thread=create)
    model.w(p,queue+0x18,CALLABLE);model.w(p,queue+0x20,CALLABLE+48);model.w(p,queue+0x28,CALLABLE+48)
    pointers=(G+0x8700,G+0x8800,h.live.TP);stacks=(G+0x20000,G+0x30000,h.live.SP)
    for index,(pointer,stack) in enumerate(zip(pointers,stacks)):
        thread=(G+0x8A00+index*0x100) if index<2 else G+0x3100
        _write_span(p,thread,bytes(0x100));model.w(p,pointer+8,thread);model.w(p,thread+0x10,(140,141,137)[index],4)
        for address in range(stack-0x8000,stack,4096):
            if address>>12 not in p:p[address>>12]=bytearray(4096)
    descriptors=((G+0x8E10,base+0x326A2C,G+0x8C00),(G+0x8E20,base+0x3260A4,G+0x8D00),threads[0])
    before={k:bytes(v) for k,v in p.items()};checkpoint=[]
    def key(staged,address,destructor):model.w(staged,address,99,4);return 0
    def wait(staged,address,operation,expected,timeout):
        assert address==queue+0x58 and service.in_lookup and model.u(staged,h.live.RECEIVER+0x28)
        assert published_configuration_value(staged,base)==7
        checkpoint.append(dict(live_reference_published=True,configuration_value=7,actual_delayed_callable_completed=True))
        return -4
    options=service.options(vm_module)
    for name in ('thread_pointer','thread_id'):options.pop(name)
    if missing_calloc:options['calloc']=None
    try:
        scheduler.run_requested_worker_schedule(p,threads=descriptors,image_base=base,libc_base=0x51000000,
            startup_entry=0x28040C,entry_stack_addresses=stacks,thread_pointers=pointers,thread_ids=(140,141,137),
            select_worker=lambda *a:2,activate_thread=lambda *a:None,create_key=key,set_specific=lambda *a:0,
            read_clock=service.read_clock,clock=lambda *a:(123,456),futex=wait,signal_condition=lambda *a:0,
            get_libc_tls=lambda *a:0,os_call=lambda *a:0,max_scheduler_steps=1,**options)
    except RefillUnsupported as error:
        if missing_calloc:assert not checkpoint and 'calloc' in str(error)
        else:assert str(error)=='cooperative scheduler selection bound exceeded' and len(checkpoint)==1
    else:raise AssertionError('worker boundary did not stop at its explicit bound')
    assert before=={k:bytes(v) for k,v in p.items()}
    return checkpoint


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument('--vm-only',action='store_true',help='Compare only the bounded lookup evaluator and its guards')
    selection.add_argument('--entries-only',action='store_true',help='Verify callable entries without repeating accepted evaluator comparisons')
    selection.add_argument('--workers-only',action='store_true',help='Verify only the live worker boundary and its rollback')
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==h.live.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.live.acquisition.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library);import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for sdk in (() if args.entries_only or args.workers_only else (27,30)):
            p,seed=fresh(args.library,args.libc,base,sdk);expected=services(seed);actual=services(seed)
            frame,top=native_setup(p,base,h.live.SP)
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            pairs=[]
            def watch(cpu,address):
                if address-base in (0x2043E0,0x2043F4,0x20440C,0x20441C,0x204428,0x204464,0x2044D0,0x2044E0,0x204458,0x20444C):
                    pairs.append((address-base,int.from_bytes(cpu.mem_read(cpu.reg_read(arm.UC_ARM64_REG_X0),8),'little')-base))
            _,memory,_,_=h.live.oracle.native(args.library,base,0x168324,
                [base+0x89650,frame+8,base+0x34F090,base+0x34F0E0,frame+0x10],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
                real_jni_acquisition=True,real_jni_dispatch=True,thread_id=137,
                extra_registers={arm.UC_ARM64_REG_SP:frame,arm.UC_ARM64_REG_TPIDR_EL0:h.live.TP},
                host_imports=expected.imports(),malloc_handler=expected.native_malloc,observed_memory=observed,
                instruction_observer=watch,instruction_limit=1000000,
                syscall_handler=lambda c,n:0 if n==98 else (_ for _ in ()).throw(AssertionError(n)))
            steps,callbacks=run_vm(p,actual,vm_full)
            assert steps==301 and callbacks==tuple(pairs),(sdk,'callbacks',callbacks,pairs)
            own=_read_span(p,G,0xA000)
            if own!=memory:
                offset=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((sdk,'guest',hex(offset),own[offset],memory[offset]))
            for (address,size),raw in observed.items():assert _read_span(p,address,size)==raw,(sdk,'image',hex(address-base))
            # Lower owners already compare logical diagnostic mutex events.
            # This evaluator comparison adds registry writer locks and checks
            # the provider boundary plus all guest pages without stack spills.
            kinds={'pthread_mutex_lock','pthread_mutex_unlock','gettid'}
            assert [e for e in actual.events if e[0] not in kinds]==expected.events,(sdk,'services',actual.events,expected.events)
            assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
            for (pointer,left),(other,right) in zip(actual.freed,expected.freed):
                assert pointer==other and left==right,('free',hex(pointer),len(left),
                    [(hex(i),a,b) for i,(a,b) in enumerate(zip(left,right)) if a!=b][:16])
            assert len(actual.freed)==len(expected.freed)
            assert model.u(p,h.live.RECEIVER+0x20,1) and model.u(p,h.live.RECEIVER+0x28)
            cases.append(dict(image_base=hex(base),sdk=sdk,component='lookup_evaluator',original_returned=True,
                VM_steps=steps,actual_callback_pairs_match=True,all_guest_payload_and_image_pages_match=True,
                JNI_JavaVM_SDK_allocator_order_match=True,all_pre_free_bytes_match=True,
                cold_live_reference_published=True,configuration_write_and_cleanup_match=True,native_snapshot_input=False))
            print('PASS live evaluator',hex(base),sdk,flush=True)
        if not args.vm_only and not args.workers_only:
            p,seed=fresh(args.library,args.libc,base,27);expected=services(seed);actual=services(seed)
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            _,memory,_,_=h.live.oracle.native(args.library,base,0x2043BC,[CALLABLE],p,libc=args.libc,
                real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
                real_jni_acquisition=True,real_jni_dispatch=True,thread_id=137,
                extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:h.live.TP},host_imports=expected.imports(),
                malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=1000000,
                syscall_handler=lambda c,n:0 if n==98 else (_ for _ in ()).throw(AssertionError(n)))
            result=run_callable(p,actual,vm_full)
            assert result.checksum_vm_steps==30 and result.lookup_vm_steps==301 and len(result.callback_pairs)==15
            assert _read_span(p,G,0xA000)==memory,'callable guest pages'
            for (address,size),raw in observed.items():assert _read_span(p,address,size)==raw,('callable image',hex(address-base))
            kinds={'pthread_mutex_lock','pthread_mutex_unlock','gettid'}
            assert [e for e in actual.events if e[0] not in kinds]==expected.events,'callable services'
            assert actual.freed==expected.freed and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
            assert model.u(p,h.live.RECEIVER+0x28) and published_configuration_value(p,base)==result.configuration_value==7
            cases.append(dict(image_base=hex(base),sdk=27,component='delayed_callable',real_entry_completed=True,
                original_returned=True,all_guest_payload_and_image_pages_match=True,JNI_JavaVM_SDK_allocator_order_match=True,
                all_pre_free_bytes_match=True,
                checksum_VM_steps=result.checksum_vm_steps,lookup_VM_steps=result.lookup_vm_steps,
                cold_live_reference_published=True,configuration_write_and_cleanup_verified=True,native_snapshot_input=False))
            print('PASS live callable',hex(base),flush=True)
        if not args.vm_only and not args.entries_only:
            for missing in (False,True):
                p,seed=fresh(args.library,args.libc,base,27);actual=services(seed)
                checkpoint=worker_boundary(p,actual,vm_full,missing_calloc=missing)
                guards.append(dict(entry='worker',case='missing_calloc' if missing else 'stop_after_live_callable',
                    rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
                if checkpoint:
                    cases.append(dict(image_base=hex(base),sdk=27,component='worker_boundary',
                        actual_delayed_callable_completed=True,cold_live_reference_published=True,
                        configuration_write_and_cleanup_verified=True,scheduler_stopped_at_explicit_bound=True,
                        all_pages_unchanged_after_stop=True,full_three_worker_schedule_compared=False,native_snapshot_input=False))
                print('PASS live worker boundary',hex(base),'missing calloc' if missing else 'callable then stop',flush=True)
    base=0x122C0000
    for entry,call in (('evaluator',run_vm),('callable',run_callable)):
        if args.workers_only:continue
        if args.entries_only and entry=='evaluator':continue
        if args.vm_only and entry=='callable':continue
        for label,changes in (('missing_JNI',dict(invoke_jni=None)),('missing_calloc',dict(calloc=None)),
                ('missing_SDK_find',dict(find_sdk_property=None)),('missing_SDK_read',dict(read_sdk_property=None)),
                ('payload_bound',dict(max_payload_bytes=1)),('JNI_failure',dict(invoke_jni=lambda *a:next(iter(()))))):
            p,seed=fresh(args.library,args.libc,base,27);service=services(seed)
            before={k:bytes(v) for k,v in p.items()}
            try:call(p,service,vm_full,**changes)
            except (RefillUnsupported,ValueError,TypeError,StopIteration):pass
            else:raise AssertionError((entry,label,'accepted'))
            assert before=={k:bytes(v) for k,v in p.items()}
            guards.append(dict(entry=entry,case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Delayed VM live provider forwarding',native_Python_evaluator_controls=sum(r['component']=='lookup_evaluator' for r in cases),
        real_callable_entry_controls=sum(r['component']=='delayed_callable' for r in cases),rollback_guards=len(guards),
        live_worker_boundary_controls=sum(r['component']=='worker_boundary' for r in cases),
        cases=cases,negative_cases=guards,delayed_VM_live_provider_wiring_verified=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,physical_register_spills_verified=False,
        live_worker_scheduler_entry_verified=any(r['component']=='worker_boundary' for r in cases),
        full_live_three_worker_schedule_compared=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS delayed providers',len(cases),'controls',len(guards),'guards',flush=True)
if __name__=='__main__':main()
