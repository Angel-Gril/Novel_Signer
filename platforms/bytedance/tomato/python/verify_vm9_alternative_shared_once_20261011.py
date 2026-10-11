"""Fresh original shared once gate for all six B controls and A regressions.

The initializer is an explicit pure provider boundary. Matching libc executes
its real broadcast body. Native memory never supplies Python input pages.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_startup_20261011 as support
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from elftools.elf.elffile import ELFFile
v=support.v;shared=support.shared;GUEST=v.oracle.GUEST
INITIALIZERS=(0x29E120,0x29E27C,0x29E3C8,0x29E514,0x29E660,0x29E7AC)


def inputs(args,base,index,state,kind='B'):
 p=v.oracle.fresh_pages();p.update(v.oracle.image_pages(args.library,base));support.setup(p,args)
 control=base+(0x3E1E80+index*8 if kind=='B' else 0x3E09E8+index*0x48)
 v.put(p,control,state)
 return p,control


def native(args,base,p,control,index,kind='B'):
 initializer=INITIALIZERS[index] if kind=='B' else 0x280890+index*0x1E4
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  broadcast=next(support.LIBC+s['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
   for s in section.iter_symbols() if s.name=='pthread_cond_broadcast' and s['st_shndx']!='SHN_UNDEF')
 expected=[];cpus=[];saved=v.oracle.Uc;mutex=base+0x3E2EB8;marker=GUEST+0x1200
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def make(*a,**kw):
  cpu=saved(*a,**kw);cpus.append(cpu);return cpu
 def observe(cpu):return [int.from_bytes(cpu.mem_read(a,n),'little') for a,n in ((control,8),(mutex,2))]
 def init(cpu):
  expected.append(('initialize',*observe(cpu)));cpu.mem_write(marker,(37+index).to_bytes(8,'little'));return 0
 def signal(cpu):
  expected.append(('broadcast',reg(cpu,0),*observe(cpu)));cpu.reg_write(v.arm.UC_ARM64_REG_PC,broadcast)
 def syscall(cpu,number):
  assert number==98 and reg(cpu,1)&0x7F==1
  expected.append(('wake',*(reg(cpu,i) for i in range(3))));return 0
 try:
  v.oracle.Uc=make
  v.oracle.native(args.library,base,0x32A0A0,[control,GUEST+0x1000,base+initializer],p,
   libc=args.libc,real_mutexes=True,host_imports={initializer:init,0x3485A0:signal},syscall_handler=syscall,
   extra_registers={v.arm.UC_ARM64_REG_TPIDR_EL0:support.TLS},instruction_limit=20000,
   code_hook_ranges=((base+initializer,base+initializer),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc=saved
 assert cpus[0].reg_read(v.arm.UC_ARM64_REG_SP)==GUEST+0xEF00
 return cpus[0],expected


def model(p,base,control,index,kind='B',changes=None):
 events=[];mutex=base+0x3E2EB8
 def observe(p):return [v.u(p,a,n) for a,n in ((control,8),(mutex,2))]
 def init(p):events.append(('initialize',*observe(p)));v.put(p,GUEST+0x1200,37+index);return 37+index
 def wake(p,*args):events.append(('wake',*args));return 0
 def broadcast(p,address):
  events.append(('broadcast',address,*observe(p)))
  return shared.objects.broadcast_condition_no_waiters(p,condition_address=address,wake=wake)
 kw=dict(image_base=base,initializer=init,broadcast=broadcast)
 kw.update(dict(control_address=control) if kind=='B' else dict(table_index=index));kw.update(changes or {})
 result=shared.call_once_arena_boot(p,**kw)
 return result,events


def compare(args,base,index,state,kind='B'):
 p,control=inputs(args,base,index,state,kind);cpu,expected=native(args,base,p,control,index,kind)
 result,events=model(p,base,control,index,kind)
 assert result==(37+index if state==0 else None) and events==expected
 for page,data in p.items():
  if GUEST+0xC000<=page<<12<GUEST+0x10000:continue
  assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),hex(page<<12)
 return dict(base=hex(base),index=index,kind=kind,initial_state=hex(state),natural_native_return=True,
  all_guest_image_libc_and_TLS_pages_match=True,ordered_initializer_broadcast_and_wake_match=True,
  actual_broadcast_body_executed=True,initializer_is_explicit_provider=True,native_snapshot_input=False)



def negative_cases(args):
 rows=[];base=0x122C0000
 def reject(label,*,index=0,changes=None,mutation=None,fault=None):
  p,control=inputs(args,base,index,0)
  if mutation:mutation(p,control)
  before={k:bytes(data) for k,data in p.items()};saved=shared._w;hits=[]
  def write(p,address,value,width=8):
   if fault(address,value,width):hits.append(address);raise RefillUnsupported('injected once write failure')
   return saved(p,address,value,width)
  try:
   if fault:shared._w=write
   try:model(p,base,control,index,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted once guard '+label)
  finally:shared._w=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
 for index in range(6):reject('busy_control_'+str(index),index=index,mutation=lambda p,c:v.put(p,c,1))
 for label,address in (('unaligned_control',base+0x3E1E81),('before_controls',base+0x3E1E78),
  ('after_controls',base+0x3E1EB0),('A_control',base+0x3E09E8),('null_control',0),('boolean_control',True)):
  reject(label,changes=dict(control_address=address))
 for value in (1,-1,True):reject('ambiguous_index_'+str(value),changes=dict(table_index=value))
 for name in ('initializer','broadcast'):reject('missing_'+name,changes={name:None})
 reject('locked_mutex',mutation=lambda p,c:v.put(p,base+0x3E2EB8,1,2))
 def fail(p):v.put(p,GUEST+0x1200,19);raise RefillUnsupported('initializer rejected')
 reject('initializer_failure',changes=dict(initializer=fail))
 def partial(p):v.put(p,GUEST+0x1200,19);return shared.ArenaBootPrefixResult(GUEST+0x4000)
 reject('partial_initializer',changes=dict(initializer=partial))
 reject('broadcast_failure',changes=dict(broadcast=lambda *a:5))
 reject('done_publication_failure',fault=lambda a,x,n:a==base+0x3E1E80 and x==(1<<64)-1)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 rows=[];guards=negative_cases(args)
 for base in (0x122C0000,0x775C205000):
  for index in range(6):
   for state in (0,(1<<64)-1,37):rows.append(compare(args,base,index,state))
   for state in (0,37):rows.append(compare(args,base,index,state,'A'))
  print('Shared B once and A regressions passed',hex(base),flush=True)
 evidence=dict(schema='vm9-alternative-shared-once-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_controls=len(rows),B_once_controls=sum(r['kind']=='B' for r in rows),
  A_once_regression_controls=sum(r['kind']=='A' for r in rows),rollback_negative_controls=len(guards),
  pre_change_behavior_RED_controls=12,actual_broadcast_body_executed=True,initializer_is_explicit_provider=True,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,
  full_B_worker_caller_composed=False,full_JNI_bootstrap_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Shared once',len(rows),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
