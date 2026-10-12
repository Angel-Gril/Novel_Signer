"""Fresh request random getter/callback, with actual matching libc rand/srand.

gettimeofday has an explicit virtual syscall provider. No random result or
state comes from the native oracle; complete nested signing remains unproved.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_request_random_fresh_20261013 as dependency
import verify_vm9_outer_signer_native as imports_owner
import vm9_request_random as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000)
LIBC_BASE=0x51000000
SP=oracle.GUEST+0xEF00
TP=oracle.GUEST+0xD000
PACKED=oracle.GUEST+0x2000
w=dependency.w


def fresh(library,libc,base,label):
    p,seed=dependency.fresh(libc,LIBC_BASE,'type_zero' if label=='type_zero' else 'default')
    p.update(oracle.image_pages(library,base))
    status=0;seconds=1791023800;micros=500000
    if label=='seconds_zero':seconds=0
    elif label=='seconds_highbit':seconds=0x80000000
    elif label=='seconds_wide':seconds=0x123456789ABCDEF0
    elif label=='failure_errno':status=-22
    elif label=='failure_outside_errno':status=-4096
    elif label=='positive_syscall_status':status=3
    elif label=='warm':w(p,base+0x3DEDB0,1)
    elif label=='guard_byte_two':w(p,base+0x3DEDB0,2)
    elif label=='completed_second_byte':w(p,base+0x3DEDB0,0x100)
    elif label=='shared_guard_mutex':w(p,base+0x3E2F40,0x2000,2)
    _write_span(p,PACKED,(base+0x26CC8C).to_bytes(8,'little')+b'\xA5'*24)
    return p,(status,seconds,micros)


class Clock:
    def __init__(self,values):self.values=values;self.calls=[]
    def write(self,writer,tv):
        status,seconds,micros=self.values
        if status>=0:writer(tv,seconds.to_bytes(8,'little')+micros.to_bytes(8,'little'))
        return status
    def native(self,c,number):
        assert number==169
        tv=c.reg_read(arm.UC_ARM64_REG_X0);tz=c.reg_read(arm.UC_ARM64_REG_X1)
        assert tz==0
        self.calls.append((number,tv,tz))
        return self.write(c.mem_write,tv)
    def model(self,p,number,args):
        assert number==169 and args[1]==0
        self.calls.append((number,*args))
        return self.write(lambda a,b:_write_span(p,a,b),args[0])


def original(library,libc,base,p,values,kind):
    clock=Clock(values);imports={}
    def redirect(entry):
        def call(c):c.reg_write(arm.UC_ARM64_REG_PC,entry)
        return call
    imports_owner.bind_native_imports(library,libc,redirect,imports)
    entry=SP-0x10 if kind=='callback' else SP
    observed={(page<<12,4096):None for page in p if
        base<=page<<12<base+0x400000 or LIBC_BASE<=page<<12<LIBC_BASE+0x100000}
    observed[TP+0x10,0x20]=None
    observed[entry-0x28,8]=None
    if kind=='time':observed[entry-0x38,0x18]=None
    else:observed[entry-0x30,8]=None
    result,memory,allocations,services=oracle.native(library,base,
        0x2728F4 if kind=='time' else 0x288B08 if kind=='callback' else 0x26CC8C,
        [PACKED] if kind in ('callback','time') else [],p,
        libc=libc,real_mutexes=True,real_singletons=True,thread_id=137,
        syscall_handler=clock.native,host_imports=imports,observed_memory=observed,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},instruction_limit=100000)
    assert not allocations and all(event[0] in ('pthread_mutex_lock','pthread_mutex_unlock','gettid') for event in services)
    return result,memory,observed,clock


def red(library,libc):
    assert not hasattr(model,'get_request_random')
    rows=[]
    for base in BASES:
        p,values=fresh(library,libc,base,'default')
        result,memory,observed,clock=original(library,libc,base,p,values,'callback')
        assert len(clock.calls)==1 and int.from_bytes(memory[0x2008:0x200C],'little')==result
        rows.append(dict(image_base=hex(base),original_random_callback_returned=True,
            explicit_time_service_and_actual_libc_seed_rand=True,
            prior_request_random_getter_missing=True,native_snapshot_input=False))
    return rows


def invoke(p,base,kind,clock,changes=None):
    kw=dict(image_base=base,libc_base=LIBC_BASE,entry_stack_address=SP,
        thread_pointer=TP,syscall=clock.model,errno_address=TP+0x10,thread_id=137)
    kw.update(changes or {})
    if kind=='time':
        return model.get_request_time_seconds(p,output_address=PACKED,
            entry_stack_address=SP,thread_pointer=TP,syscall=clock.model,errno_address=TP+0x10)
    if kind=='callback':kw['argument_block_address']=PACKED
    return (model.store_request_random_callback if kind=='callback' else model.get_request_random)(p,**kw)


def compare(library,libc,base,kind,label):
    p,values=fresh(library,libc,base,label)
    returned,memory,observed,expected=original(library,libc,base,p,values,kind)
    actual=Clock(values);result=invoke(p,base,kind,actual)
    assert returned==result and actual.calls==expected.calls,(kind,label,'return/syscalls')
    assert _read_span(p,oracle.GUEST,0xA000)==memory,(kind,label,'guest')
    for (a,n),raw in observed.items():
        current=_read_span(p,a,n)
        if current!=raw:
            i=next(i for i,(x,y) in enumerate(zip(current,raw)) if x!=y)
            raise AssertionError((kind,label,'observed',hex(a+i),current[i],raw[i]))
    print('PASS random getter',hex(base),kind,label,flush=True)
    return dict(image_base=hex(base),kind=kind,case=label,original_returned=True,
        random_W_return_guest_ELF_libc_TLS_and_canaries_equal=True,
        gettimeofday_errno_and_low_W_seed_equal=True,actual_libc_guard_rand_srand_mutexes=kind!='time',
        callback_W_store_and_padding_equal=True,clock_calls=len(actual.calls),native_snapshot_input=False)


def guards(library,libc):
    rows=[]
    for label in ('contended_guard','contended_random_mutex','unmapped_state','missing_time_provider',
            'invalid_syscall_result','time_provider_canary_mutation','unaligned_stack','missing_thread_id'):
        base=BASES[0];p,values=fresh(library,libc,base,'default');clock=Clock(values);kw={}
        if label=='contended_guard':w(p,base+0x3DEDB0,0x200)
        elif label=='contended_random_mutex':w(p,LIBC_BASE+0xDFB30,1,2)
        elif label=='unmapped_state':w(p,LIBC_BASE+0xDA210,0x66000000)
        elif label=='missing_time_provider':kw['syscall']=None
        elif label=='invalid_syscall_result':kw['syscall']=lambda *a:1<<64
        elif label=='time_provider_canary_mutation':
            def mutate(p,n,args):w(p,TP+0x28,0);return clock.model(p,n,args)
            kw['syscall']=mutate
        elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
        elif label=='missing_thread_id':kw['thread_id']=None
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,base,'getter',clock,kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--libc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','native','guards','all'),default='all')
    args=p.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    e=dict(schema='vm9-request-random-getter-fresh-v1',evidence_date='2026-10-13',
        sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=dependency.LIBC_SHA256,cases=[],negative_cases=[],
        native_snapshot_input=False,private_names_or_payloads_published=False,
        whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        nested_request_random_callback_integrated=False)
    if args.group=='red':e['red_cases']=red(args.library,args.libc)
    if args.group in ('native','all'):
        profiles=[('getter',n) for n in ('default','type_zero','seconds_zero','seconds_highbit','seconds_wide',
            'failure_errno','failure_outside_errno','positive_syscall_status','warm','guard_byte_two',
            'completed_second_byte','shared_guard_mutex')]+[('callback',n) for n in ('default','warm','seconds_wide')]+[
            ('time',n) for n in ('default','seconds_wide','failure_errno','failure_outside_errno','positive_syscall_status')]
        e['cases']=[compare(args.library,args.libc,b,k,n) for b in BASES for k,n in profiles]
    if args.group in ('guards','all'):e['negative_cases']=guards(args.library,args.libc)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS random getter',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
