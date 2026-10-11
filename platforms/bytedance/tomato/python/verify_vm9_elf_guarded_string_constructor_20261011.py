"""Fresh actual ELF guarded string constructor against Python pages.

The allocator, thread id and exit registration are explicit guest services.
Original C++ guard bodies and matching-libc mutexes execute normally.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from verify_vm9_root_configuration import LIBC_BASE
import verify_vm9_elf_support_constructors_20261011 as previous
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_elf_bootstrap as bootstrap
v=previous.v

def prepare(args,base,entry,profile):
 p=previous.prepare(args,base,profile.get('padding',0xA5),profile.get('stack_padding',0))
 if profile.get('padded_object'):
  for a,n in ((0x3D1DA8,96),(0x3D1E88,24),(0x3E3230,8)):_write_span(p,base+a,b'\x39'*n)
 if profile.get('warm_cache'):
  for a,n in ((0x3DF0A8,0x555555),(0x3DF0C0,0x515151),(0x3DF0C8,0x616161)):_write_span(p,base+a,n.to_bytes(8,'little'))
 return p

def native(args,p,base,entry,profile,sp=v.SP,return_address=None):
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE,v.oracle.STOP;cpus=[];cursor=previous.previous.ARENA+profile.get('allocation_delta',0);events=[]
 stop=return_address or saved[2]
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(previous.previous.ARENA,previous.previous.ARENA_SIZE);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  nonlocal cursor
  a=0 if profile.get('malloc_NULL') else cursor
  if a:cursor+=(max(size,1)+15)&~15
  events.append(('allocate',size,a));return a
 def register(cpu):
  status=profile.get('registration_status',0);events.append(('register',*(reg(cpu,i) for i in range(3)),status&0xFFFFFFFF));return status&0xFFFFFFFF
 def clock(cpu):
  identifier=reg(cpu,0);status=profile.get('clock_status',0);sec,ns=profile.get('time',(123,987654321))
  events.append(('clock',identifier,status,sec,ns))
  cpu.mem_write(reg(cpu,1),(sec&((1<<64)-1)).to_bytes(8,'little')+ns.to_bytes(8,'little'));return status&0xFFFFFFFF
 def aux(cpu):
  value=profile.get('auxval',0);events.append(('auxval',reg(cpu,0),value));return value
 def property(cpu):
  name,out=reg(cpu,0),reg(cpu,1);status=profile.get('property_status',0)
  value=bytes(cpu.mem_read(base+0x6EC1E,10)) if profile.get('property_matches') else b'fixture\0'
  if status>0:cpu.mem_write(out,value)
  events.append(('property',name,out,status));return status&0xFFFFFFFF
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream);symbols=elf.get_section_by_name('.dynsym').get_symbol_by_name('strncmp');assert len(symbols)==1
  strncmp_entry=LIBC_BASE+symbols[0]['st_value']
 def strncmp(cpu):cpu.reg_write(v.arm.UC_ARM64_REG_PC,strncmp_entry);return None
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000;v.oracle.STOP=stop
  v.oracle.native(args.library,base,entry,[],p,libc=args.libc,malloc_handler=allocate,real_mutexes=True,real_singletons=True,thread_id=profile.get('thread_id',137),
   host_imports={0x347EA0:register,0x348450:clock,0x348330:aux,0x3486D0:property,0x348400:strncmp},
   extra_registers={v.arm.UC_ARM64_REG_SP:sp},instruction_limit=1000000)
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE,v.oracle.STOP=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_PC)==stop and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,events



def model(p,base,profile,sp,changes=None):
 cursor=previous.previous.ARENA+profile.get('allocation_delta',0);events=[]
 def allocate(p,size):
  nonlocal cursor
  address=0 if profile.get('malloc_NULL') else cursor
  if address:cursor+=(max(size,1)+15)&~15
  events.append(('allocate',size,address));return address
 def register(p,fn,obj,dso):
  status=profile.get('registration_status',0);events.append(('register',fn,obj,dso,status&0xFFFFFFFF));return status
 kw=dict(image_base=base,constructor_entry=0x15DB50,entry_stack_address=sp,
  allocate=allocate,register_exit=register,thread_id=profile.get('thread_id',137))
 kw.update(changes or {})
 return bootstrap.run_support_constructor(p,**kw),events


def fixture(args,base,profile):
 p=previous.prepare(args,base,0x15DB50,profile)
 if 'guard' in profile:_write_span(p,base+0x3D1418,profile['guard'])
 if profile.get('padded_guard'):_write_span(p,base+0x3D141A,b'\x39'*2)
 if profile.get('padded_object'):_write_span(p,base+0x3D1400,b'\xA5'*24)
 if profile.get('redirect_destructor'):_write_span(p,base+0x374F28,(base+0x2484FC).to_bytes(8,'little'))
 return p


def compare(args,base,label,profile,sp):
 p=fixture(args,base,profile);cpu,expected=native(args,p,base,0x15DB50,profile,sp)
 result,events=model(p,base,profile,sp)
 assert events==expected and result.entry==0x15DB50
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  if v.oracle.GUEST+0xA000<=page<<12<v.oracle.GUEST+0x10000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,allocations=len(result.allocations),registrations=len(result.finalizers),
  warm_guard_skipped=(not events),natural_return_SP_verified=True,all_guest_heap_image_libc_pages_match=True,
  ordered_allocation_and_registration_match=True,guard_thread_id_and_padding_match=True,native_snapshot_input=False)


def negatives(args):
 base=0x122C0000;rows=[]
 def reject(label,profile=None,changes=None,fault=None):
  profile=profile or {};p=fixture(args,base,profile);before={k:bytes(data) for k,data in p.items()}
  saved=bootstrap._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected guard constructor failure')
   return saved(p,a,d)
  try:
   if fault:bootstrap._write_span=write
   try:model(p,base,profile,v.SP,changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted guard constructor '+label)
  finally:bootstrap._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (('missing_thread',dict(thread_id=None)),('boolean_thread',dict(thread_id=True)),
  ('zero_thread',dict(thread_id=0)),('thread_overflow',dict(thread_id=1<<32)),
  ('missing_allocator',dict(allocate=None)),('unmapped_allocator',dict(allocate=lambda *a:0x76000000)),
  ('frame_allocator',dict(allocate=lambda *a:v.SP-0x100)),('image_allocator',dict(allocate=lambda *a:base+0x3D2000)),
  ('missing_registration',dict(register_exit=None)),('registration_overflow',dict(register_exit=lambda *a:1<<32)),
  ('late_registration_refusal',dict(register_exit=lambda *a:(_ for _ in ()).throw(RefillUnsupported('registration refused'))))):reject(label,changes=changes)
 for byte in (2,4,6,255):reject('guard_pending_'+str(byte),dict(guard=bytes([0,byte,0,0,0,0,0,0])))
 for label,slot,width in (('guard_thread',0x3D141C,4),('guard_state',0x3D1419,1),
  ('string',0x3D1400,24),('global_mutex',0x3E2F40,40),('final_guard_publication',0x3D1418,1)):
  reject('reserved_'+label,changes=dict(reserved_regions=((base+slot,base+slot+width),)))
  reject('write_failure_'+label,fault=lambda a,d:a==base+slot)
 print('Guard rollback controls',len(rows),'passed',flush=True)
 return rows


PROFILES=[('cold',{}),('nonzero_registration',dict(registration_status=7)),('padded_object',dict(padded_object=True)),
 ('NULL_malloc',dict(malloc_NULL=True)),('padded_guard_thread1',dict(padded_guard=True,thread_id=1)),
 ('alternate_allocator_destructor',dict(allocation_delta=0xC00,redirect_destructor=True)),
 ('warm_guard',dict(guard=b'\1'+bytes(7))),('acquire_warm_byte0',dict(guard=b'\2'+bytes(7))),
 ('acquire_completed_byte1',dict(guard=b'\0\1'+bytes(6)))]


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base,delta in ((0x122C0000,0),(0x775C205000,-0xC80)):
  for label,profile in PROFILES:
   profile=dict(profile,padding=0xA5 if not delta else 0xFF,stack_padding=0 if not delta else 0x39)
   rows.append(compare(args,base,label,profile,v.SP+delta));print('Guard constructor',hex(base),label,'passed',flush=True)
 evidence=dict(schema='vm9-elf-guarded-string-constructor-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=8,
  guarded_string_constructor_implemented=True,fresh_independent_ELF_inputs=True,native_input_snapshot_used=False,
  private_names_or_payloads_published=False,full_ELF_loader_verified=False,full_JNI_bootstrap_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Guard constructor controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
