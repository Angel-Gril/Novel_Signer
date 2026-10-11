"""Fresh full ELF constructors -> JNI -> conditional startup composition.

Original instructions execute in one native run. Python maps and links its
own ELF, runs all constructors and JNI/startup owners. Worker requests remain
deferred. Compare complete surviving pages and ordered service groups; private
ELF names, decoded payloads and native snapshots are never published inputs.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import vm9_jni_bootstrap as owner
import vm9_startup as shared
import verify_vm9_elf_constructor_sequence_20261011 as sequence
import verify_vm9_elf_image_loader_20261011 as image
import verify_vm9_alternative_startup_20261011 as startup_fixture
import verify_vm9_jni_cold_once_fresh_20261008 as cold
from vm9_allocator import _read_span,_write_span,RefillUnsupported

GUEST=sequence.v.oracle.GUEST;ENV_TABLE=GUEST+0x6000;DISPATCH=sequence.DISPATCH
ARENA=sequence.ARENA;MASK64=(1<<64)-1

def fresh(args,base,profile,*,Python=False):
    p=sequence.configuration.fixture(args,base,profile)
    if Python:
        resolve,_=image.provider(args,base)
        loaded=image.owner.load_elf_image(args.library.read_bytes(),image_base=base,resolve_symbol=resolve).pages
    else:loaded=image.reference(args,base,args.library.read_bytes())[0]
    p.update(loaded);startup_fixture.setup(p,args,profile.get('thread_id',137))
    for address in (cold.acquisition.TABLE,ENV_TABLE):_write_span(p,address,bytes(4096))
    def word(a,v):_write_span(p,a,v.to_bytes(8,'little'))
    word(cold.acquisition.VM,cold.acquisition.TABLE)
    for slot,fn in ((0x20,cold.acquisition.ATTACH),(0x28,cold.acquisition.DETACH),(0x30,cold.acquisition.GET)):
        word(cold.acquisition.TABLE+slot,fn)
    word(cold.ENV,ENV_TABLE);word(cold.INNER_ENV,ENV_TABLE)
    for i,slot in enumerate(cold.initialization.SLOTS):word(ENV_TABLE+slot,GUEST+0xF210+i*0x10)
    for i,slot in enumerate(cold.EXTRA):word(ENV_TABLE+slot,GUEST+0xF400+i*0x10)
    return p

class Services(sequence.Services):
    def __init__(self,base,profile):super().__init__(base,profile);self.threads=[]
    def create_thread(self,p,out,attr,start,arg):
        assert attr==0
        handle=GUEST+0xC800+len(self.threads)*0x100
        _write_span(p,out,handle.to_bytes(8,'little'));self.threads.append((handle,start,arg))
        self.events.append(('thread',attr,start,arg,handle));return 0
    def signal(self,p,address):
        self.events.append(('signal',address))
        return shared.signal_condition_no_waiters(p,condition_address=address,wake=self.wake)
    def jni(self,p,sp,word,vm_module,changes=None):
        vm=cold.acquisition.Providers(self.base,None,[(0,cold.ENV)]*4)
        jni=cold.JNI(self.base,dict(self.profile,long_word=word))
        jni.dispatch_sp=jni.long_sp=sp-0x320
        def cold_wake(p,address,operation,count):
            # The switch owner executes the bionic broadcast body directly.
            # Record that internal call where its explicit wake service runs,
            # to match the original PLT observation without invoking it twice.
            assert address==self.base+0x3E2EE0 and operation==129 and count==0x7FFFFFFF
            self.events.append(('broadcast',address))
            return self.wake(p,address,operation,count)
        kw=dict(image_base=self.base,entry_stack_address=sp,entry_return_address=DISPATCH,
            java_vm_address=cold.acquisition.VM,thread_pointer=sequence.configuration.TP,
            thread_id=self.profile.get('thread_id',137),allocate=self.allocate,free=self.free,
            read_clock=self.clock,get_tls=self.get_tls,initialize_registry=self.initialize,
            broadcast=self.broadcast,parse_decimal=self.decimal,register_exit=self.register,
            register_thread_destructor=self.destructor,invoke_javavm=vm.model_vm,
            invoke_jni=jni.model,wake_condition=cold_wake,create_thread=self.create_thread,
            signal_condition=self.signal,vm_module=vm_module)
        kw.update(changes or {})
        result=owner.run_jni_onload(p,**kw)
        assert not vm.responses and not jni.checks
        return result,vm,jni


def native(args,p,base,profile,sp,word):
    service=Services(base,profile);vm=cold.acquisition.Providers(base,None,[(0,cold.ENV)]*4)
    jni=cold.JNI(base,dict(profile,long_word=word));saved=sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE
    cpus=[];pending_once=False;returns=[];scopes=[];startup_entries=[]
    entries=sequence.array_entries(args,p,base)+(0x27B41C,)
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:sequence.LIBC_BASE+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    def reg(cpu,i):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
    def factory(*a,**kw):
        cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000)
        cpu.mem_map(ARENA,sequence.support.previous.ARENA_SIZE);cpus.append(cpu);return cpu
    def clock(cpu):
        status,sec,ns=service.clock(None,reg(cpu,0))
        cpu.mem_write(reg(cpu,1),(sec&MASK64).to_bytes(8,'little')+ns.to_bytes(8,'little'));return status
    def decimal(cpu):
        service.events.append(('strtol',*(reg(cpu,i) for i in range(3))))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['strtol']);return None
    def jump(name):
        def call(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,exports[name]);return None
        return call
    def property(cpu):
        status=profile.get('property_status',0)
        if status>0:cpu.mem_write(reg(cpu,1),bytes(cpu.mem_read(base+0x6EC1E,10)))
        service.events.append(('property',reg(cpu,0),reg(cpu,1),status));return status
    def once(cpu):
        nonlocal pending_once
        assert reg(cpu,0)==base+0x3E31F8 and reg(cpu,1)==base+0x343980
        state=int.from_bytes(cpu.mem_read(base+0x3E31F8,4),'little')
        if state==0:
            cpu.mem_write(base+0x3E31F8,(1).to_bytes(4,'little'));pending_once=True
            cpu.reg_write(arm.UC_ARM64_REG_PC,base+0x343980);return None
        assert state==2;return 0
    def create_key(cpu):
        key=service.next_key;service.next_key+=1
        service.events.append(('key_create',reg(cpu,0),reg(cpu,1),key));cpu.mem_write(reg(cpu,0),key.to_bytes(4,'little'));return 0
    def realloc(cpu):
        old,n=reg(cpu,0),reg(cpu,1);a=service.allocate(None,n)
        cpu.mem_write(a,bytes(cpu.mem_read(old,min(service.sizes[old],n))));return a
    def broadcast(cpu):
        service.events.append(('broadcast',reg(cpu,0)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_broadcast']);return None
    def signal(cpu):
        service.events.append(('signal',reg(cpu,0)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_signal']);return None
    def create_thread(cpu):
        assert reg(cpu,1)==0
        handle=GUEST+0xC800+len(service.threads)*0x100
        service.threads.append((handle,reg(cpu,2),reg(cpu,3)))
        service.events.append(('thread',reg(cpu,1),reg(cpu,2),reg(cpu,3),handle))
        cpu.mem_write(reg(cpu,0),handle.to_bytes(8,'little'));return 0
    def syscall(cpu,number):
        assert number==98;return service.wake(None,*(reg(cpu,i) for i in range(3)))
    def observe(cpu,address):
        nonlocal pending_once
        if pending_once and address==base+0x343818:
            cpu.mem_write(base+0x3E31F8,(2).to_bytes(4,'little'));pending_once=False
        if address==base+0x26C858:scopes.append(reg(cpu,0))
        if address==base+0x26E70C:jni.dispatch_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if address==base+0x270854:jni.long_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        if address-base in (0x2A0028,0x28040C):startup_entries.append(address-base)
        if address==DISPATCH:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
            returns.append(reg(cpu,0))
            if len(returns)==len(entries):cpu.reg_write(arm.UC_ARM64_REG_PC,sequence.v.oracle.STOP)
            else:
                if len(returns)==13:
                    cpu.reg_write(arm.UC_ARM64_REG_X0,cold.acquisition.VM);cpu.reg_write(arm.UC_ARM64_REG_X1,0)
                cpu.reg_write(arm.UC_ARM64_REG_X30,DISPATCH);cpu.reg_write(arm.UC_ARM64_REG_PC,base+entries[len(returns)])
    imports={fn-base:vm.imports()[fn-base] for fn in (cold.acquisition.GET,cold.acquisition.ATTACH,cold.acquisition.DETACH)}
    imports.update(jni.imports());imports.update({0x347EA0:lambda c:service.register(None,*(reg(c,i) for i in range(3))),
        0x348450:clock,0x3484B0:decimal,0x348330:lambda c:service.aux(None,reg(c,0)),
        0x347FE0:jump('memcmp'),0x348400:jump('strncmp'),0x3486D0:property,0x3486B0:once,
        0x348620:create_key,0x3485D0:lambda c:service.get(None,reg(c,0)),
        0x348580:lambda c:service.setvalue(None,reg(c,0),reg(c,1)),0x348320:realloc,
        0x347FA0:lambda c:service.free(None,reg(c,0)),0x3485A0:broadcast,0x348590:signal,0x348000:create_thread})
    offsets=(0x343818,0x26C858,0x26E70C,0x270854,0x2A0028,0x28040C)
    ranges=((DISPATCH,DISPATCH),(base+0x347E00,base+0x348800),
        (GUEST+0xF180,GUEST+0xF1A0),(GUEST+0xF210,GUEST+0xF450),*((base+a,base+a) for a in offsets))
    try:
        sequence.v.oracle.Uc=factory;sequence.v.oracle.GUEST_SIZE=0x160000
        sequence.v.oracle.native(args.library,base,entries[0],[],p,libc=args.libc,
            malloc_handler=lambda c,n:service.allocate(None,n),host_imports=imports,
            real_mutexes=True,real_diagnostics=True,real_recursive_mutexes=True,
            real_singletons=True,real_jni_acquisition=True,real_jni_dispatch=True,
            thread_id=profile.get('thread_id',137),syscall_handler=syscall,instruction_observer=observe,
            extra_registers={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X30:DISPATCH},
            instruction_limit=120000000,code_hook_ranges=ranges)
    finally:sequence.v.oracle.Uc,sequence.v.oracle.GUEST_SIZE=saved
    assert len(returns)==14 and returns[-1]==0x10006 and not vm.responses and not jni.checks
    assert startup_entries==[0x2A0028 if word&0x200 else 0x28040C]
    print('Original all13 +JNI +conditional startup naturally returned',hex(base),hex(word),flush=True)
    return cpus[0],service,vm,jni,scopes


def compare(args,base,profile,sp,word,initial,initial_service,constructors,vm_module):
    native_input=fresh(args,base,profile)
    cpu,expected,expected_vm,expected_jni,scopes=native(args,native_input,base,profile,sp,word)
    p={k:bytearray(v) for k,v in initial.items()}
    actual=Services(base,profile)
    actual.cursor=initial_service.cursor;actual.events=list(initial_service.events)
    actual.sizes=dict(initial_service.sizes);actual.specific=dict(initial_service.specific);actual.next_key=initial_service.next_key
    result,vm,jni=actual.jni(p,sp,word,vm_module)
    modules=[r for r in constructors.constructor_results if hasattr(r,'effects')]
    owners={e.address:i for i,r in enumerate(modules) for e in r.effects if e.kind=='allocate'}
    streams=[[(('allocate',e.size,e.address) if e.kind=='allocate' else ('free',e.address)) for e in r.effects] for r in modules]
    modeled=[];seen=set()
    for event in actual.events:
        if event[0] not in ('allocate','free'):continue
        if event[0]=='allocate' and event[2] in owners:
            index=owners[event[2]]
            if index not in seen:modeled.extend(streams[index]);seen.add(index)
        else:modeled.append(event)
    assert modeled==[e for e in expected.events if e[0] in ('allocate','free')]
    for kinds in ({'atexit'},{'thread'},set(e[0] for e in expected.events)-{'allocate','free','atexit','thread'}):
        actual_group=[e for e in actual.events if e[0] in kinds];expected_group=[e for e in expected.events if e[0] in kinds]
        assert actual_group==expected_group,(kinds,actual_group,expected_group)
    assert vm.events==expected_vm.events and jni.events==expected_jni.events and actual.threads==expected.threads
    assert actual.sizes==expected.sizes and actual.specific==expected.specific
    for page,data in p.items():
        if 0x78000000<=page<<12<0x78200000:continue
        if GUEST+0xA000<=page<<12<GUEST+0x10000:continue
        actual_bytes=bytes(cpu.mem_read(page<<12,4096))
        assert bytes(data)==actual_bytes,(hex(base),hex(word),hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual_bytes)) if x!=y][:12])
    assert result.jni_version==0x10006 and result.switch_word==word and result.startup_entry==(0x2A0028 if word&0x200 else 0x28040C)
    executor=int.from_bytes(_read_span(p,base+0x3E2D78,8),'little')
    for index,vt in ((0,0x35FC28 if word&0x200 else 0x35D630),(1,0x34F010)):
        queue=int.from_bytes(_read_span(p,executor+index*8,8),'little')
        vector=int.from_bytes(_read_span(p,queue+0x18,8),'little')
        assert int.from_bytes(_read_span(p,vector,8),'little')==base+vt
        assert int.from_bytes(_read_span(p,queue+0x20,8),'little')-vector==48
    row=dict(base=hex(base),switch_word=hex(word),startup_entry=hex(result.startup_entry),
        original_constructor_returns=13,original_JNI_version=hex(result.jni_version),
        JNI_service_calls=len(jni.events),JavaVM_service_calls=len(vm.events),thread_requests=len(actual.threads),
        diagnostic_scopes=len(scopes),allocation_free_effect_count=len(modeled),
        natural_same_execution_JNI_return_SP_verified=True,all_surviving_guest_heap_image_libc_pages_match=True,
        ordered_allocation_free_registration_OS_JNI_VM_thread_groups_match=True,
        main_and_finalizer_queue_callables_match=True,exactly_one_conditional_startup_executed=True,
        fresh_independent_ELF_inputs=True,native_snapshot_input=False,
        module_registration_allocation_interleaving_compared=False,physical_native_stack_and_thread_output_scratch_compared=False,
        workers_executed=False)
    print('Complete JNI/bootstrap Python comparison',hex(base),hex(word),'passed',flush=True);return row


def negatives(initial,initial_service,vm_module):
    rows=[];base=initial_service.base;sp=sequence.v.SP
    def reject(label,changes=None,mutation=None):
        p={k:bytearray(v) for k,v in initial.items()}
        if mutation:mutation(p)
        before={k:bytes(v) for k,v in p.items()};s=Services(base,{})
        s.cursor=initial_service.cursor;s.sizes=dict(initial_service.sizes);s.specific=dict(initial_service.specific);s.next_key=initial_service.next_key
        try:s.jni(p,sp,0x200,vm_module,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('accepted JNI guard '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    for label,changes in (
        ('unaligned_base',dict(image_base=base+1)),('unaligned_SP',dict(entry_stack_address=sp+1)),
        ('zero_return',dict(entry_return_address=0)),('zero_VM',dict(java_vm_address=0)),
        ('unaligned_TP',dict(thread_pointer=sequence.configuration.TP+1)),('zero_thread',dict(thread_id=0)),
        ('boolean_thread',dict(thread_id=True)),('step_budget',dict(max_steps=0)),
        ('depth_budget',dict(max_depth=0)),('node_budget',dict(max_nodes=0)),
        ('invalid_reserved',dict(reserved_regions=((2,1),))),('reserved_caller',dict(reserved_regions=((sp-0x100,sp),))),
        ('GetEnv_status_overflow',dict(invoke_javavm=lambda *a:1<<32)),
        ('late_signal_refusal',dict(signal_condition=lambda *a:11)),
        ('decimal_wrong_target',dict(parse_decimal=lambda *a:0)),
        ('decimal_type',dict(parse_decimal=lambda *a:True)),
        ('thread_failure',dict(create_thread=lambda *a:11)),
        ('NULL_allocator',dict(allocate=lambda *a:0)),
        ('late_clock_failure',dict(read_clock=lambda *a:(1,0,0)))):reject(label,changes)
    for name in ('allocate','free','read_clock','get_tls','initialize_registry','broadcast','parse_decimal','register_exit',
        'register_thread_destructor','invoke_javavm','invoke_jni','wake_condition','create_thread','signal_condition'):
        reject('missing_'+name,{name:None})
    reject('wrong_defined_JNI_GOT',mutation=lambda p:_write_span(p,base+0x375010,bytes(8)))
    reject('wrong_JNI_entry_code',mutation=lambda p:_write_span(p,base+0x27B41C,bytes(4)))
    reject('wrong_class_selector',mutation=lambda p:_write_span(p,base+0x382898,bytes(8)))
    reject('wrong_finalizer_clone',mutation=lambda p:_write_span(p,base+0x204330,bytes(4)))
    reject('wrong_finalizer_destructor',mutation=lambda p:_write_span(p,base+0x34F030,bytes(8)))
    print('Complete JNI rollback guards',len(rows),'passed',flush=True);return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==sequence.v.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==sequence.v.defined.builder.catalog.heap.LIBC_HASH
    os.environ['TOMATO_LIBMETASEC']=str(args.library);import vm_full
    rows=[];guard_input=guard_service=None
    for base,delta,profile in ((0x122C0000,0,{}),(0x775C205000,-0xC80,dict(allocation_delta=0xC00,thread_id=1,padding=0xFF,stack_padding=0x39))):
        initial=fresh(args,base,profile,Python=True);service=Services(base,profile);sp=sequence.v.SP+delta
        constructors=service.sequence(initial,sp)
        print('Fresh independent all13 Python constructor context ready',hex(base),flush=True)
        if not delta:guard_input,guard_service=initial,service
        for word in (0,0x200):rows.append(compare(args,base,profile,sp,word,initial,service,constructors,vm_full))
    guards=negatives(guard_input,guard_service,vm_full)
    evidence=dict(schema='vm9-jni-complete-bootstrap-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=sequence.v.oracle.LIBRARY_SHA256,matching_libc_sha256=sequence.v.defined.builder.catalog.heap.LIBC_HASH,
        native_Python_complete_JNI_bootstrap_controls=len(rows),rollback_controls=len(guards),pre_change_native_RED_controls=2,
        full_ELF_mapping_linking_constructor_JNI_main_startup_composition_verified=True,
        fresh_independent_ELF_inputs=True,native_input_snapshot_used=False,private_names_or_payloads_published=False,
        full_same_execution_worker_and_cleanup_verified=False,host_JVM_or_real_concurrency_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Complete JNI/bootstrap GREEN',len(rows),'controls',len(guards),'guards',flush=True)

if __name__=='__main__':main()
