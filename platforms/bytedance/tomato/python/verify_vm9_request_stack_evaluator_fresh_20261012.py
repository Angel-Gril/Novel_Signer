"""Fresh +0x28b05c JNI stack evaluator versus original ELF execution.

JavaVM/JNI services and a warm singleton are independently constructed inputs.
Original acquisition, wrappers, comparison helpers and cleanup execute normally.
Payload/image pages, service order, logical va_lists and getter SPs are compared.
Physical spills, a real Android JVM, cold singleton and signing remain separate.
"""
from pathlib import Path
import argparse, hashlib, json, os
from unicorn import arm64_const as arm
import verify_vm9_jni_live_lookup_fresh_20261011 as h
import vm9_jni_environment as environment
import vm9_registry as registry
import vm9_request_leaf_prefixes as leaf
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=h.G; DESC=G+0x1600; NAME=G+0x1700; FIRST=G+0x8000; SECOND=G+0x8400
COUNTS={0x30:2,0x388:4,0x398:4,0x108:4,0x118:4,0x558:2,0x568:3,
        0x548:3,0x550:3,0x720:1,0x78:1,0x88:1,0xB8:2}
BASES=(0x122C0000,0x775C205000)


def fresh(library,base,profile):
    p,blocks=h.fresh(library,base,27)
    h.owner.w(p,h.acquisition.OWNER+16,h.ENV)
    h.owner.w(p,base+0x3D1680,1,1);h.owner.w(p,base+0x3D1678,G+0x7000)
    h.owner.w(p,G+0x7000,G+0x7200);h.owner.w(p,G+0x7008,1)
    _write_span(p,G+0x7200,bytes(136))
    h.owner.w(p,G+0x7210,profile.get('first_field',0))
    h.owner.w(p,G+0x7218,profile.get('second_field',0))
    for slot in COUNTS:h.owner.w(p,h.TABLE+slot,G+0xF600+slot//2)
    _write_span(p,NAME,profile.get('method',b'expected_method')+b'\0')
    for i in range(3):
        expected=G+0x2100+i*0x100
        h.owner.w(p,DESC+i*8,0 if profile.get('null_descriptor') else expected)
        name=b'expected_class' if i==0 or profile.get('same_descriptors') else b'another_expected'
        _write_span(p,expected,name+b'\0')
        first=profile.get('first',b'unexpected_method')
        if isinstance(first,tuple):first=first[i]
        _write_span(p,FIRST+i*0x100,first+b'\0')
        _write_span(p,SECOND+i*0x100,profile.get('second',b'unexpected_class')+b'\0')
    return p,blocks


class Services(h.Services):
    def __init__(self,base,blocks,profile):
        super().__init__(base,27,blocks,profile)
        self.classes=0;self.methods=0;self.current=0;self.strings={};self.va_lists=[]
    def jni(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2
        assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==h.ENV
        result=0;label='';profile=self.profile
        if slot==0x30:
            label='class'+str(self.classes);result=h.CLS+self.classes*16;self.classes+=1
        elif slot==0x388:label='static_id';result=h.METHOD
        elif slot==0x108:
            label=('trace_id','first_id','second_id')[self.methods]
            result=h.METHOD+16+self.methods*16;self.methods+=1
        elif slot==0x398:label='static_object';result=h.OBJECT
        elif slot==0x118:
            role=(args[2]-h.METHOD-16)//16
            if role==0:label='trace_object';result=h.ARRAY
            else:
                kind=role-1;label='string'+str(self.current)+'_'+str(kind)
                result=G+0x7100+self.current*0x40+kind*16
                self.strings[result]=(self.current,kind)
        elif slot==0x558:label='length';result=profile.get('array_length',4)
        elif slot==0x568:
            self.current=args[2]-2;label='element'+str(self.current);result=h.ELEMENT+args[2]*16
        elif slot==0x548:
            index,kind=self.strings[args[1]];label='utf'+str(index)+'_'+str(kind)
            result=(FIRST if kind==0 else SECOND)+index*0x100
        elif slot==0x720:result=int(self.pending)
        elif slot==0x78:result=0 if profile.get('null_exception') else h.EXCEPTION
        elif slot==0x88:self.pending=False
        else:assert slot in (0x550,0xB8)
        if label==profile.get('null_at'):result=0
        if label==profile.get('exception_at'):self.pending=True
        if slot in (0x398,0x118):
            self.va_lists.append((args[3],read(args[3],32),read(args[3]+0x28,32)))
            expected=h.SP-0xF0
            raw=b''.join(v.to_bytes(8,'little') for v in (expected,expected-0x70,expected-0xA0))
            raw+=(-40).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
            assert self.va_lists[-1][1:]==(raw,raw)
        self.events.append(['JNI',slot,*args,result&h.owner.MASK64])
        return result&h.owner.MASK64
    def imports(self):
        imports=super().imports()
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                return self.jni(fn,tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count)),
                    lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-self.base]=call
        if self.profile.get('null_environment'):
            def acquire_null(c):
                pair=c.reg_read(arm.UC_ARM64_REG_X0)
                self.events.append(['NULL_acquisition',c.reg_read(arm.UC_ARM64_REG_SP),pair])
                c.mem_write(pair,bytes(16));return 0
            imports[0x26EDC4]=acquire_null
        return imports
    def acquire(self,p,**kw):
        if self.profile.get('null_environment'):
            self.events.append(['NULL_acquisition',kw['entry_stack_address'],kw['output_pair_address']])
            _write_span(p,kw['output_pair_address'],bytes(16));return None
        return environment.acquire_thread_environment(p,image_base=self.base,
            get_tls=self.vm.tls,register_destructor=self.vm.register,invoke_javavm=self.vm.model_vm,**kw)
    def getter(self,p,sp):
        self.events.append(['singleton_getter',sp])
        def forbidden(*a,**kw):raise AssertionError('explicit warm singleton became cold')
        return registry.get_singleton136_reference(p,entry_stack_address=sp,image_base=self.base,
            allocate=self.malloc,free=self.free,read_clock=forbidden,get_tls=forbidden,
            initialize_registry=forbidden,broadcast=forbidden,thread_id=137).wrapper_address
    def execute(self,p,**kw):
        options=dict(image_base=self.base,entry_stack_address=h.SP,descriptor_address=DESC,
            descriptor_count=self.profile.get('descriptor_count',2),
            method_name_address=0 if self.profile.get('null_method') else NAME,
            acquire_environment=self.acquire,invoke_jni=self.model_jni,get_singleton=self.getter)
        options.update(kw);return leaf.execute_stack_evaluator_prefix(p,**options)


def compare(library,libc,base,label,profile):
    p,blocks=fresh(library,base,profile);expected=Services(base,blocks,profile);actual=Services(base,blocks,profile)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    observed[h.SP-0xE0,16]=None
    def watch(c,pc):
        if pc==base+0x161068:expected.events.append(['singleton_getter',c.reg_read(arm.UC_ARM64_REG_SP)])
    result,memory,_,_=h.oracle.native(library,base,0x28B05C,
        [DESC,profile.get('descriptor_count',2),0 if profile.get('null_method') else NAME],p,
        libc=libc,real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_jni_acquisition=True,real_jni_dispatch=True,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:h.TP},
        thread_id=137,host_imports=expected.imports(),malloc_handler=expected.native_malloc,
        instruction_observer=watch,observed_memory=observed,instruction_limit=500000)
    out=actual.execute(p)
    assert result==out,('return',label,result,out)
    assert h.oracle.flatten(p)[:0xA000]==memory,('payload',label)
    assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),('image/pair',label)
    assert expected.events==actual.events,('order',label,expected.events,actual.events)
    assert expected.va_lists==actual.va_lists,('va_lists',label)
    row=dict(image_base=hex(base),case=label,native_return=result,
        all_guest_payload_and_image_pages_match=True,environment_pair_match=True,
        JNI_JavaVM_and_singleton_getter_order_match=True,logical_va_lists_match=True,
        original_wrappers_comparisons_and_cleanup_executed=True,
        original_acquisition_executed=not profile.get('null_environment',False),
        explicit_NULL_acquisition_boundary=profile.get('null_environment',False),native_snapshot_input=False)
    print('PASS evaluator',hex(base),label,'return',result,flush=True)
    return row


def request_entry(library,libc):
    """Fresh owning outer -> actual request VM -> evaluator, then bounded stop."""
    os.environ['TOMATO_LIBMETASEC']=str(library.resolve())
    import vm_full
    import verify_vm9_outer_constructor_boundary as boundary
    import verify_vm9_request_prefix_fresh_20261007 as prefix
    import verify_vm9_worker_allocator as worker
    import verify_vm9_root_configuration as fixture
    import vm9_outer_allocator as outer
    from vm9_allocator import _PageTransaction
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    sessions=[];previous=outer.make_session;rows=[];guards=[];base=BASES[1]
    def make(*a,**kw):
        session=previous(*a,**kw);sessions.append(session);return session
    def w(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))
    def terminal(pages,*,result,**unused):
        session=next(s for s in sessions if s.pages is pages)
        p=_PageTransaction(pages)
        prefix.resolve_request_memory_imports(p,library,base)
        request=worker.TOP+0x100;_write_span(p,request,bytes(0x800))
        import vm9_registry as registry
        import vm9_objects as objects
        descriptor=request+0x100
        _write_span(p,descriptor,b''.join((base+offset).to_bytes(8,'little')
            for offset in (0x182D6C,0x182D6C,0x188A94)))
        header=session.allocate(p,40)
        registry.construct_configuration_tree(p,container_address=header,
            descriptor_address=descriptor,image_base=base,allocate=session.allocate)
        objects.construct_reference_wrapper(p,object_address=request,
            referenced_address=header,allocate=session.allocate)
        handler=int.from_bytes(_read_span(p,result.callback_pair_addresses[0]+8,8),'little')
        inputs=dict(entry_stack_address=worker.TOP,return_address=0xDEAD0000,thread_pointer=fixture.TLS,
            image_base=base,argument_x0=handler,argument_x1=request,argument_x2=0,
            argument_x3=request+0x200,output_x8=request+0x400)
        vm=session.allocate(p,64);vm_table=session.allocate(p,64)
        env=session.allocate(p,8);table=session.allocate(p,0x800)
        w(p,base+0x3DEED8,vm);w(p,vm,vm_table);w(p,vm_table+0x30,0x7400F000);w(p,env,table)
        for slot in (0x30,0x720):w(p,table+slot,0x7400F100+slot)
        for label in ('JNI_connected','missing_JNI','JNI_provider_exception',
                      'missing_counter_TLS','counter_TLS_provider_exception','NULL_header_reference',
                      'missing_exit_service','exit_provider_exception','fill_allocator_exception',
                      'missing_fold_singleton','fold_singleton_exception'):
            events=[];diag={'thread_id':session.thread_id}
            def invoke_vm(p,fn,args):
                assert fn==0x7400F000 and args[0]==vm and args[2]==0x10006
                events.append('GetEnv');w(p,args[1],env);return 0
            def acquire(p,**kw):
                return environment.acquire_thread_environment(p,image_base=base,**kw,
                    get_tls=session.get_tls,register_destructor=session.thread_destructor,invoke_javavm=invoke_vm)
            def jni(p,fn,args):
                assert args[0]==env and fn in (0x7400F130,0x7400F820)
                events.append('FindClass' if fn==0x7400F130 else 'ExceptionCheck')
                if label=='JNI_provider_exception':raise RefillUnsupported('injected request JNI failure')
                return 0
            def counter_tls(p,control):
                if label=='counter_TLS_provider_exception':
                    raise RefillUnsupported('injected request counter TLS failure')
                return session.get_tls(p,control)
            def register_exit(p,*args):
                if label=='exit_provider_exception':
                    raise RefillUnsupported('injected request process exit registration failure')
                return session.register_destructor(p,*args)
            def request_singleton(p,sp):
                if label=='fold_singleton_exception' and diag.get('request_cstring_lengths'):
                    w(p,request+0x700,0xA5)
                    raise RefillUnsupported('injected request folded singleton failure')
                return session.singleton(p,sp)
            def request_allocate(p,n):
                if label=='fill_allocator_exception' and diag.get('request_process_registrations'):
                    w(p,request+0x700,0xA5)
                    raise RefillUnsupported('injected request fill allocation failure')
                return session.allocate(p,n)
            if label=='NULL_header_reference':w(p,request,0)
            before={k:bytes(v) for k,v in p.items()}
            try:
                prefix.execute_prefix(p,inputs,vm_full,1791023800,500000000,
                    allocate=request_allocate,diagnostic_scope=diag,reallocate=session.reallocate,free=session.free,
                    prepare_format=session.prepare_format,read_clock=session.read_clock,acquire_environment=acquire,
                    invoke_jni=None if label=='missing_JNI' else jni,get_singleton=None if label=='missing_fold_singleton' else request_singleton,
                    get_tls=None if label=='missing_counter_TLS' else counter_tls,
                    initialize_registry=session.initialize_registry,broadcast=session.broadcast,
                    register_exit=None if label=='missing_exit_service' else register_exit)
            except prefix.RequestContinuationBoundary as exc:
                assert before=={k:bytes(v) for k,v in p.items()}
                if label=='JNI_connected':
                    assert exc.vm.steps==1995 and exc.vm.pc-base==0xFECE0
                    assert str(exc.cause)=='unknown request callback +0x285f44 -> +0x25c150'
                    assert events==['GetEnv','GetEnv','FindClass','ExceptionCheck']
                    completed=diag['request_evaluator_prefixes'][-1]
                    assert completed['phase']=='stack_evaluator_completed' and not completed['returned_boolean']
                    scope=diag['request_boolean_scopes'][-1]
                    assert scope['phase']=='boolean_scope_completed' and scope['emission_calls']==1
                    gate=diag['request_byte_gates'][-1]
                    assert gate['phase']=='request_byte_gate_completed' and gate['returned_byte']==0
                    assert gate['actual_target_offset']=='0x28bb54'
                    request_object=diag['request_objects'][-1]
                    assert request_object['phase']=='request_object_lifecycle_completed'
                    address=request_object['object_address']
                    assert int.from_bytes(_read_span(exc.staged,address,8),'little')==base+0x35B868
                    counter=int.from_bytes(_read_span(exc.staged,address+0x30,8),'little')
                    assert int.from_bytes(_read_span(exc.staged,counter,4),'little')==1
                    count=diag['request_counters'][-1]
                    assert count['phase']=='request_counter_completed' and count['previous_u32']==0 and count['inserted']
                    tree=diag['request_trees'][-1]
                    assert tree['phase']=='request_tree_constructed'
                    assert {r['position'] for r in diag['request_tree_iterators']}=={'begin','end'}
                    assert diag['request_iterator_comparisons'][-1]['equal']
                    registration=diag['request_process_registrations'][-1]
                    assert registration['status_u32']==0 and registration['owning_exit_service_used']
                    fill=diag['request_fill_strings'][-1]
                    assert fill['length_u32']==16 and fill['fill_byte']==0
                    assert diag['request_tree_lookups']==[dict(found=False)]
                    assert diag['request_cstring_lengths'][:2]==[10,4]
                    assert diag['request_folded_comparisons'] and all(isinstance(v,int) for v in diag['request_folded_comparisons'])
                    rows.append(dict(image_base=hex(base),case=label,request_vm_steps=1995,
                        actual_request_callback_and_evaluator_executed=True,owning_TLS_allocator_and_JavaVM_used=True,
                        explicit_NULL_FindClass_input=True,evaluator_completed=True,
                        actual_scope_cleanup_completed=True,actual_request_byte_gate_completed=True,
                        actual_request_object_constructed=True,temporary_reference_released_to_one_owner=True,
                        actual_request_counter_completed=True,owning_TLS_registry_and_broadcast_used=True,
                        valid_empty_header_container_input=True,actual_tree_and_iterators_completed=True,
                        iterator_comparison_completed=True,unresolved_process_atexit_import=False,
                        actual_process_atexit_registration_completed=True,
                        actual_fill_string_constructor_completed=True,
                        actual_tree_lookup_completed=True,actual_NULL_safe_cstring_lengths_completed=True,
                        actual_guest_table_folded_comparisons_completed=True,owning_fold_singleton_used=True,
                        stopped_at_wrapper_offset='0x285f44',stopped_at_callback_offset='0x25c150',
                        all_pages_unchanged_after_stop=True,
                        full_request_returned=False,whole_handoff_native_differential_verified=False))
                elif label in ('missing_fold_singleton','fold_singleton_exception'):
                    assert exc.vm.steps==1812 and exc.vm.pc-base==0xFADA8
                    expected='folded comparison requires a singleton getter' if label=='missing_fold_singleton' else 'injected request folded singleton failure'
                    assert str(exc.cause)==expected
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
                elif label=='fill_allocator_exception':
                    assert exc.vm.steps==1558 and exc.vm.pc-base==0xF9D38
                    assert str(exc.cause)=='injected request fill allocation failure'
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
                elif label in ('missing_exit_service','exit_provider_exception'):
                    assert exc.vm.steps==1539 and exc.vm.pc-base==0xF9CEC
                    expected='process destructor registration requires an exit service' if label=='missing_exit_service' else 'injected request process exit registration failure'
                    assert str(exc.cause)==expected
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
                elif label=='NULL_header_reference':
                    assert exc.vm.steps==1452 and exc.vm.pc-base==0xF9A28
                    assert str(exc.cause)=='missing checkpoint page 0x0'
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
                elif label in ('missing_counter_TLS','counter_TLS_provider_exception'):
                    assert exc.vm.steps==1419 and exc.vm.pc-base==0xF99A4
                    expected='registry counter requires allocator/free and scoped TLS services' if label=='missing_counter_TLS' else 'injected request counter TLS failure'
                    assert str(exc.cause)==expected
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
                else:
                    assert exc.vm.steps==965 and exc.vm.pc-base==0xF8FD0
                    expected='request JNI FindClass +0x28b71c is not recovered' if label=='missing_JNI' else 'injected request JNI failure'
                    assert str(exc.cause)==expected
                    guards.append(dict(image_base=hex(base),entry='request_VM',case=label,rejected=True,
                        all_pages_unchanged=True,external_effects_rolled_back=False))
            else:raise AssertionError('request unexpectedly completed')
            if label=='NULL_header_reference':w(p,request,header)
            steps=1995 if label=='JNI_connected' else 1812 if label in ('missing_fold_singleton','fold_singleton_exception') else 1558 if label=='fill_allocator_exception' else 1539 if label in ('missing_exit_service','exit_provider_exception') else 1452 if label=='NULL_header_reference' else 1419 if 'counter_TLS' in label else 965
            print('PASS request VM',label,steps,'steps',flush=True)
    try:
        outer.make_session=make
        result=boundary.case(library,libc,base,'absent',None,vm_full,apply_logger_model=True,
            apply_handoff_model=True,apply_publication=True,terminal_observer=terminal)
    finally:outer.make_session=previous
    assert result['python_constructor_returned'] and result['publication_applied'] and len(rows)==1 and len(guards)==10
    return rows,guards


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('core','branches','guards','entry','all'),default='all')
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==h.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.acquisition.LIBC_SHA256
    core=[('mismatch',{}),('method_prefix',dict(first=b'expected_method_suffix')),
        ('short_method_prefix',dict(first=b'expected_meth')),('empty_first',dict(first=b'')),
        ('class_prefix',dict(first=b'expected_class_suffix',same_descriptors=True)),
        ('second_utf_unused',dict(second=b'expected_class',first=b'unexpected_method')),
        ('descriptor_cursor_after_NULL_element',dict(null_at='element0',first=b'expected_class')),
        ('descriptor_cursor_after_NULL_UTF',dict(null_at='utf0_0',first=b'expected_class')),
        ('NULL_descriptor',dict(null_descriptor=True)),('NULL_method',dict(null_method=True)),
        ('short_array',dict(array_length=2)),('signed_array_length',dict(array_length=0xFFFFFFFF)),
        ('zero_descriptors',dict(descriptor_count=0)),('wrapped_descriptors',dict(descriptor_count=0xFFFFFFFF)),
        ('signed_limit_wrap',dict(descriptor_count=0x7FFFFFFE)),
        ('three_frames',dict(array_length=5,descriptor_count=3)),
        ('one_checked_field',dict(first_field=G+0x7600)),('NULL_environment',dict(null_environment=True))]
    branches=[]
    for label in ('class0','static_id','static_object','trace_id','trace_object','class1','first_id','second_id',
                  'element0','string0_0','string0_1','utf0_0','utf0_1'):
        branches.append(('NULL_'+label,dict(null_at=label)))
    for label in ('class0','static_object','trace_object','length','class1','string0_0','string0_1'):
        branches.append(('exception_'+label,dict(exception_at=label)))
    branches.append(('NULL_exception_reference',dict(exception_at='string0_0',null_exception=True)))
    cases=[];guards=[];entries=[]
    selected=(core if args.group in ('core','all') else [])+(branches if args.group in ('branches','all') else [])
    for base in BASES:
        for label,profile in selected:cases.append(compare(args.library,args.libc,base,label,profile))
    if args.group in ('guards','all'):
        for base in BASES:
            for label in ('missing_acquisition','missing_JNI','missing_getter','frame_bound','string_bound',
                          'missing_table','missing_release','JNI_provider_exception','checked_environment'):
                profile=dict(first_field=G+0x7600,second_field=G+0x7700) if label=='checked_environment' else {}
                p,blocks=fresh(args.library,base,profile);services=Services(base,blocks,profile);kw={}
                if label=='missing_acquisition':kw['acquire_environment']=None
                elif label=='missing_JNI':kw['invoke_jni']=None
                elif label=='missing_getter':kw['get_singleton']=None
                elif label=='frame_bound':kw['max_frames']=1
                elif label=='string_bound':kw['max_string_bytes']=1
                elif label=='missing_table':h.owner.w(p,h.ENV,0)
                elif label=='missing_release':h.owner.w(p,h.TABLE+0x550,0)
                elif label=='JNI_provider_exception':
                    def fail(*a):raise RefillUnsupported('injected JNI service failure')
                    kw['invoke_jni']=fail
                before={k:bytes(v) for k,v in p.items()}
                try:services.execute(p,**kw)
                except RefillUnsupported:pass
                else:raise AssertionError('guard completed: '+label)
                assert before=={k:bytes(v) for k,v in p.items()},label
                guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,
                    external_effects_rolled_back=False))
                print('PASS rollback',hex(base),label,flush=True)
    if args.group in ('entry','all'):
        entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
    args.output.write_text(json.dumps(dict(cases=cases,request_entry_cases=entries,negative_cases=guards,
        native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
        warm_singleton_component_boundary=True,private_names_or_payloads_published=False,
        physical_register_spills_verified=False,cold_singleton_composition_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
    print('PASS',len(cases),'native controls,',len(guards),'rollback guards',flush=True)


if __name__=='__main__':main()
