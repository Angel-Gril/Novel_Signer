"""Original first timed submission versus independently constructed Python pages."""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_startup_b_callable_20261011 as callables
import verify_vm9_signer_objects as oracle
import vm9_startup as startup
import vm9_timed_tasks as owner
from vm9_allocator import _read_span,_write_span,RefillUnsupported

GUEST=oracle.GUEST;SOURCE=GUEST+0x1000;SELECTOR=GUEST+0x1100
EXECUTOR=GUEST+0x2000;PAYLOAD=GUEST+0x2200;CONTEXT=GUEST+0x2400
SCRATCH=GUEST+0xB000;LIBC=0x51000000
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def inputs(args,base,index,padding):
    p=oracle.fresh_pages();p.update(oracle.image_pages(args.library,base))
    for address,size in ((EXECUTOR,32),(PAYLOAD,32),(CONTEXT,0xE8)):
        _write_span(p,address,bytes(size))
    w(p,SOURCE,base+0x34F058);w(p,SOURCE+0x20,SOURCE);w(p,SELECTOR,index,1)
    w(p,base+0x3E2D80,1,1);w(p,base+0x3E2D78,EXECUTOR)
    w(p,EXECUTOR+0x10,PAYLOAD);w(p,PAYLOAD,base+0x372648);w(p,PAYLOAD+8,CONTEXT)
    w(p,CONTEXT,u(p,base+0x3750B8)+0x10);w(p,CONTEXT+8,u(p,base+0x3750B8)+0x48)
    w(p,CONTEXT+0x69,1,1);w(p,CONTEXT+0x78,u(p,base+0x3750C0)+0x10)
    w(p,CONTEXT+0xE0,CONTEXT+0x78)
    _write_span(p,GUEST+0x4000,bytes([padding])*0x5000)
    return p


class Providers:
    def __init__(self,base,padding,delta=0):
        self.base=base;self.padding=padding;self.cursor=GUEST+0x4000+delta;self.events=[]
    def allocate(self,p,n):
        address=self.cursor;self.cursor+=(n+15)&~15
        self.events.append(('allocate',n,address));_write_span(p,address,bytes([self.padding])*n)
        return address
    def free(self,p,address):self.events.append(('free',address))
    def clock(self,p,key):self.events.append(('clock',key,123,987654321));return 123,987654321
    def signal(self,p,address):
        self.events.append(('signal',address))
        return startup.signal_condition_no_waiters(p,condition_address=address,wake=self.wake)
    def wake(self,p,address,operation,count):
        self.events.append(('wake',address,operation,count));return 0


def model(p,base,index,delay,s):
    return owner.submit_timed_callable(p,source_address=SOURCE,scratch_address=SCRATCH,
        image_base=base,queue_index=index,delay_ms=delay,allocate=s.allocate,free=s.free,
        clock=s.clock,signal_condition=s.signal)


def compare(args,base,index,delay,padding,delta=0):
    p=inputs(args,base,index,padding);s=Providers(base,padding,delta);expected=Providers(base,padding,delta)
    old=oracle.Uc;cpus=[]
    def factory(*a,**kw):cpu=old(*a,**kw);cpus.append(cpu);return cpu
    def reg(cpu,i):return cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
    def allocate(cpu,n):
        address=expected.cursor;expected.cursor+=(n+15)&~15
        expected.events.append(('allocate',n,address));cpu.mem_write(address,bytes([padding])*n);return address
    def clock(cpu):
        sec,ns=expected.clock(None,reg(cpu,0));cpu.mem_write(reg(cpu,1),sec.to_bytes(8,'little')+ns.to_bytes(8,'little'));return 0
    with args.libc.open('rb') as stream:
        exports={sym.name:LIBC+sym['st_value'] for sym in ELFFile(stream).get_section_by_name('.dynsym').iter_symbols() if sym['st_shndx']!='SHN_UNDEF'}
    def signal(cpu):
        expected.events.append(('signal',reg(cpu,0)))
        cpu.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_signal']);return None
    def syscall(cpu,number):
        assert number==98 and reg(cpu,1)==129 and reg(cpu,2)==1
        return expected.wake(None,*(reg(cpu,i) for i in range(3)))
    try:
        oracle.Uc=factory
        oracle.native(args.library,base,0x325454,[SELECTOR,SOURCE,delay&0xFFFFFFFF],p,
            libc=args.libc,real_mutexes=True,malloc_handler=allocate,syscall_handler=syscall,
            host_imports={0x348450:clock,0x348590:signal,0x347FA0:lambda c:expected.free(None,reg(c,0)) or 0})
    except Exception:
        cpu=cpus[0]
        print('Timed native failure',*[hex(cpu.reg_read(r)) for r in (arm.UC_ARM64_REG_PC,arm.UC_ARM64_REG_LR,arm.UC_ARM64_REG_SP)],expected.events,flush=True)
        raise
    finally:oracle.Uc=old
    result=model(p,base,index,delay,s)
    assert cpus[0].reg_read(arm.UC_ARM64_REG_SP)==GUEST+0xEF00
    assert s.events==expected.events,(s.events,expected.events)
    for page,data in p.items():
        if GUEST+0xA000<=page<<12<GUEST+oracle.GUEST_SIZE:continue
        actual=bytes(cpus[0].mem_read(page<<12,4096))
        assert bytes(data)==actual,hex(page<<12)
    assert result.deadline_milliseconds==123987+delay
    assert u(p,result.task_address+0x20)==result.callable_address
    assert startup._executor_head(p,CONTEXT,64)[1]==result.task_address
    return dict(base=hex(base),queue_index=index,delay_ms=delay,padding=padding,allocation_delta=delta,
        allocations=sum(e[0]=='allocate' for e in s.events),natural_return_and_SP_match=True,
        complete_surviving_guest_and_image_pages_match=True,ordered_provider_effects_match=True,
        heap_callable_task_and_first_deque_match=True,native_snapshot_input=False)


def negatives(args):
    rows=[];base=0x122C0000
    for label,changes,mutation in (
        ('zero_delay',dict(delay_ms=0),None),('boolean_delay',dict(delay_ms=True),None),
        ('wide_delay',dict(delay_ms=1<<31),None),('unknown_queue',dict(queue_index=2),None),
        ('boolean_queue',dict(queue_index=True),None),('unaligned_image',dict(image_base=base+1),None),
        ('unaligned_source',dict(source_address=SOURCE+1),None),('unaligned_scratch',dict(scratch_address=SCRATCH+1),None),
        ('overlapping_scratch',dict(scratch_address=SOURCE),None),
        ('missing_allocate',dict(allocate=None),None),('missing_free',dict(free=None),None),
        ('missing_clock',dict(clock=None),None),('missing_signal',dict(signal_condition=None),None),
        ('null_allocation',dict(allocate=lambda *a:0),None),
        ('failed_signal',dict(signal_condition=lambda *a:11),None),
        ('invalid_clock',dict(clock=lambda *a:(123,1000000000)),None),
        ('uninitialized_executor',{},lambda p:w(p,base+0x3E2D80,0,1)),
        ('cancelled_executor',{},lambda p:w(p,CONTEXT+0x68,1,1)),
        ('inactive_controller',{},lambda p:w(p,CONTEXT+0x69,0,1)),
        ('nonempty_deque',{},lambda p:w(p,CONTEXT+0x60,1)),
        ('unknown_source',{},lambda p:w(p,SOURCE,base+0x34F010)),
        ('changed_clone_slot',{},lambda p:w(p,base+0x34F058+0x18,0)),
        ('changed_clone_code',{},lambda p:w(p,base+0x2043A4,0)),
        ('changed_virtual_method',{},lambda p:w(p,u(p,CONTEXT),0)),
        ('changed_controller',{},lambda p:w(p,CONTEXT+0xE0,0)),
    ):
        p=inputs(args,base,1,0xA5);s=Providers(base,0xA5)
        if mutation:mutation(p)
        before={k:bytes(v) for k,v in p.items()}
        kw=dict(source_address=SOURCE,scratch_address=SCRATCH,image_base=base,queue_index=1,delay_ms=60000,
            allocate=s.allocate,free=s.free,clock=s.clock,signal_condition=s.signal);kw.update(changes)
        try:owner.submit_timed_callable(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('accepted guard '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    guards=negatives(args);rows=[]
    for base in (0x122C0000,0x775C205000):
        for index,delay,padding,delta in ((1,60000,0xA5,0),(0,1,0,0),(1,-1,0xFF,0x200),(0,2147483647,0x39,0x400)):
            rows.append(compare(args,base,index,delay,padding,delta))
        print('Timed submission',hex(base),'PASS',flush=True)
    callable_rows=[callables.compare(args,base,0x34F058,label) for base in (0x122C0000,0x775C205000)
        for label in ('move_inline','move_heap','move_empty','destroy_inline','destroy_heap','reset_inline','reset_heap','assign_inline','assign_heap','assign_self_inline','assign_self_heap','assign_replace')]
    evidence=dict(schema='vm9-timed-task-submission-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,native_Python_timed_controls=len(rows),callable_controls=len(callable_rows),
        rollback_controls=len(guards),native_input_snapshot_used=False,private_names_or_payloads_published=False,
        actual_finalizer_worker_composed=False,timed_followup_callback_executed=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,callable_cases=callable_rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('Timed submission GREEN',len(rows),'controls',len(callable_rows),'callables',len(guards),'guards',flush=True)

if __name__=='__main__':main()
