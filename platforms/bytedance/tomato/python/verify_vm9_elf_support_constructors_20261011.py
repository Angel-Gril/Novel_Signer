"""Fresh original ELF support constructors against independent Python pages.

Explicit clock/auxv/property/allocator/registration services are inputs.
Matching-libc mutex and strncmp bodies execute on the original side.
Private ELF strings and payloads remain runtime inputs, never evidence data.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
import verify_vm9_alternative_constructor_20261011 as previous
from verify_vm9_root_configuration import LIBC_BASE
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_elf_bootstrap as bootstrap
v=previous.v
ENTRIES=(0x17319C,0x180D28,0x1834E4,0x271940,0x28300C,0x343A84)

def prepare(args,base,entry,profile):
 p=previous.prepare(args,base,profile.get('padding',0xA5),profile.get('stack_padding',0))
 if profile.get('padded_object'):
  for a,n in ((0x3D1DA8,96),(0x3D1E88,24),(0x3E3230,8)):_write_span(p,base+a,b'\x39'*n)
 if profile.get('warm_cache'):
  for a,n in ((0x3DF0A8,0x555555),(0x3DF0C0,0x515151),(0x3DF0C8,0x616161)):_write_span(p,base+a,n.to_bytes(8,'little'))
 return p

def native(args,p,base,entry,profile,sp=v.SP,return_address=None):
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE,v.oracle.STOP;cpus=[];cursor=previous.ARENA+profile.get('allocation_delta',0);events=[]
 stop=return_address or saved[2]
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(previous.ARENA,previous.ARENA_SIZE);cpus.append(cpu);return cpu
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
  v.oracle.native(args.library,base,entry,[],p,libc=args.libc,malloc_handler=allocate,real_mutexes=True,
   host_imports={0x347EA0:register,0x348450:clock,0x348330:aux,0x3486D0:property,0x348400:strncmp},
   extra_registers={v.arm.UC_ARM64_REG_SP:sp},instruction_limit=1000000)
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE,v.oracle.STOP=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_PC)==stop and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,events


def model(p,base,entry,profile,sp=v.SP,return_address=None,changes=None):
 cursor=previous.ARENA+profile.get('allocation_delta',0);events=[]
 def allocate(p,size):
  nonlocal cursor
  address=0 if profile.get('malloc_NULL') else cursor
  if address:cursor+=(max(size,1)+15)&~15
  events.append(('allocate',size,address));return address
 def register(p,fn,obj,dso):
  status=profile.get('registration_status',0);events.append(('register',fn,obj,dso,status&0xFFFFFFFF));return status
 def clock(p,identifier):
  status=profile.get('clock_status',0);sec,ns=profile.get('time',(123,987654321))
  events.append(('clock',identifier,status,sec,ns));return status,sec,ns
 def aux(p,key):
  value=profile.get('auxval',0);events.append(('auxval',key,value));return value
 def property(p,name,out):
  status=profile.get('property_status',0)
  value=_read_span(p,base+0x6EC1E,10) if profile.get('property_matches') else b'fixture\0'
  if status>0:_write_span(p,out,value)
  events.append(('property',name,out,status));return status
 kw=dict(image_base=base,constructor_entry=entry,entry_stack_address=sp,
  entry_return_address=return_address or v.oracle.STOP,allocate=allocate,register_exit=register,
  read_clock=clock,get_auxval=aux,get_property=property)
 kw.update(changes or {})
 result=bootstrap.run_support_constructor(p,**kw)
 return result,events


def extra_fixture(p,base,profile):
 if profile.get('warm_table'):
  address=int.from_bytes(_read_span(p,base+0x379968,8),'little')-0xE6FDE0
  _write_span(p,address,(0x778899).to_bytes(8,'little'))
 if profile.get('redirect_GOT'):
  _write_span(p,base+0x374F80,(v.oracle.GUEST+0x6000).to_bytes(8,'little'))
  _write_span(p,base+0x379968,(v.oracle.GUEST+0x6010+0xE6FDE0).to_bytes(8,'little'))
 if profile.get('redirect_destructor'):
  _write_span(p,base+0x374F28,(base+0x2484FC).to_bytes(8,'little'))


def compare(args,base,entry,label,profile,sp,stop):
 p=prepare(args,base,entry,profile);extra_fixture(p,base,profile)
 cpu,expected=native(args,p,base,entry,profile,sp,stop)
 result,events=model(p,base,entry,profile,sp,stop)
 assert events==expected,(hex(entry),label,events,expected)
 assert result.entry==entry
 assert list(result.allocations)==[(e[2],e[1]) for e in events if e[0]=='allocate']
 assert list(result.finalizers)==[tuple(e[1:]) for e in events if e[0]=='register']
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  # Existing oracle native stack and TP backing pages are not live outputs.
  if v.oracle.GUEST+0xA000<=page<<12<v.oracle.GUEST+0x10000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(hex(entry),label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),entry=hex(entry),label=label,service_count=len(events),
  allocations=len(result.allocations),finalizers=len(result.finalizers),publications=len(result.publication_addresses),
  natural_return_SP_verified=True,all_guest_heap_image_libc_pages_match=True,
  ordered_services_and_registration_statuses_match=True,relocated_GOT_inputs_used=True,
  native_snapshot_input=False,physical_native_stack_compared=False)


PROFILES={
 0x17319C:[('cold',{}),('warm_table',dict(warm_table=True)),('redirect_GOT',dict(redirect_GOT=True)),
  ('negative_seconds',dict(time=(-1,5))),('wrapped_signed_time',dict(time=(9223372036854775807,999999999)))],
 0x180D28:[('cold',{}),('padded_objects',dict(padded_object=True)),('nonzero_registration',dict(registration_status=-1))],
 0x1834E4:[('cold',{}),('NULL_malloc',dict(malloc_NULL=True)),('padded_relocated_destructor',dict(padded_object=True,redirect_destructor=True)),
  ('alternate_allocation_nonzero_registration',dict(allocation_delta=0xC00,registration_status=7))],
 0x271940:[('cold',{}),('warm_cache',dict(warm_cache=True)),('alternate_allocation_nonzero_registration',dict(allocation_delta=0xC00,registration_status=7))],
 0x28300C:[('cold',{}),('negative_seconds',dict(time=(-1,5))),('wrapped_time',dict(time=(9223372036854775807,999999999)))],
 0x343A84:[('aux_bit_clear',dict(auxval=0xFEFF)),('missing_property',dict(auxval=256,property_status=0)),
  ('negative_property_status',dict(auxval=256,property_status=-1)),('different_property',dict(auxval=256,property_status=7)),
  ('matching_property',dict(auxval=256,property_status=10,property_matches=True)),
  ('high_aux_bits',dict(auxval=0xFFFFFFFFFFFFFFFF,property_status=10,property_matches=True))],
}


def negatives(args):
 base=0x122C0000;rows=[]
 def reject(entry,label,profile=None,changes=None,fault=None):
  profile=profile or {};p=prepare(args,base,entry,profile);before={k:bytes(data) for k,data in p.items()}
  saved=bootstrap._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected support constructor failure')
   return saved(p,a,d)
  try:
   if fault:bootstrap._write_span=write
   try:model(p,base,entry,profile,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted support guard '+label)
  finally:bootstrap._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for entry in (True,0,0x2679F0,0x15DB54):reject(entry,'unsupported_entry_'+str(entry))
 for label,changes in (('boolean_image',dict(image_base=True)),('unaligned_image',dict(image_base=base+1)),
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('missing_return_address',dict(entry_return_address=None)),('invalid_reserved_region',dict(reserved_regions=((2,1),)))):
  reject(0x17319C,label,changes=changes)
 for entry,slot in ((0x17319C,0x3D17C8),(0x180D28,0x3D1DC0),(0x1834E4,0x3D1E88),(0x271940,0x3DF118),(0x28300C,0x3E0B58),(0x343A84,0x3E3230)):
  reject(entry,'reserved_publication_'+hex(entry),changes=dict(reserved_regions=((base+slot,base+slot+8),)))
  reject(entry,'publication_failure_'+hex(entry),fault=lambda a,d:a==base+slot)
 for entry in (0x17319C,0x28300C):
  reject(entry,'missing_clock_'+hex(entry),changes=dict(read_clock=None))
  reject(entry,'clock_failure_'+hex(entry),profile=dict(clock_status=-1))
  reject(entry,'invalid_timespec_'+hex(entry),profile=dict(time=(1,1000000000)))
 for entry in (0x180D28,0x1834E4,0x271940):
  reject(entry,'missing_register_'+hex(entry),changes=dict(register_exit=None))
  reject(entry,'late_register_refusal_'+hex(entry),changes=dict(register_exit=lambda *a:(_ for _ in ()).throw(RefillUnsupported('registration refused'))))
  reject(entry,'register_status_overflow_'+hex(entry),changes=dict(register_exit=lambda *a:1<<32))
 for entry in (0x1834E4,0x271940):
  for label,callback in (('missing_allocator',None),('unmapped_allocator',lambda *a:0x76000000),
   ('frame_allocator',lambda *a:v.SP-0x100),('image_allocator',lambda *a:base+0x3D2000)):
   reject(entry,label+'_'+hex(entry),changes=dict(allocate=callback))
 reject(0x271940,'NULL_operator_new',changes=dict(allocate=lambda *a:0))
 reject(0x343A84,'missing_auxv',changes=dict(get_auxval=None))
 reject(0x343A84,'invalid_auxv',changes=dict(get_auxval=lambda *a:1<<64))
 reject(0x343A84,'missing_property',profile=dict(auxval=256),changes=dict(get_property=None))
 reject(0x343A84,'property_status_overflow',profile=dict(auxval=256),changes=dict(get_property=lambda *a:1<<32))
 reject(0x343A84,'property_scratch_reserved',profile=dict(auxval=256),changes=dict(reserved_regions=((v.SP-0x70,v.SP),)))
 print('Support constructor guards',len(rows),'passed',flush=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base,delta in ((0x122C0000,0),(0x775C205000,-0xC80)):
  for entry in ENTRIES:
   for label,profile in PROFILES[entry]:
    profile=dict(profile,padding=0xA5 if not delta else 0xFF,stack_padding=0 if not delta else 0x39)
    rows.append(compare(args,base,entry,label,profile,v.SP+delta,v.oracle.STOP+(0x80 if delta else 0)))
   print('Support constructor',hex(base),hex(entry),'passed',flush=True)
 evidence=dict(schema='vm9-elf-support-constructors-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=12,
  supported_ELF_support_constructors=6,fresh_independent_ELF_inputs=True,native_input_snapshot_used=False,
  matching_libc_mutex_and_strncmp_executed=True,private_names_or_payloads_published=False,
  full_ELF_loader_verified=False,full_JNI_bootstrap_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Support constructor controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
