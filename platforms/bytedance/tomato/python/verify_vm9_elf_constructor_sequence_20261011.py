"""Original full init_array versus independent Python owner composition.

Compare shared caches, allocations, all surviving pages and each ordered
allocation/free and registration stream. Retired native stack saves and
module registration interleaving with allocation are outside this contract.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from verify_vm9_root_configuration import LIBC_BASE
import verify_vm9_elf_configuration_constructor_20261011 as configuration
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_elf_bootstrap as bootstrap
v=configuration.v
support=configuration.support
ARENA=configuration.ARENA;DISPATCH=configuration.DISPATCH;MASK64=configuration.MASK64

class Services(configuration.Services):
 def aux(self,p,key):
  value=self.profile.get('auxval',0);self.events.append(('auxval',key,value));return value
 def property(self,p,name,out):
  status=self.profile.get('property_status',0)
  if status>0:_write_span(p,out,_read_span(p,self.base+0x6EC1E,10))
  self.events.append(('property',name,out,status));return status
 def sequence(self,p,sp,changes=None):
  kw=dict(image_base=self.base,entry_stack_address=sp,entry_return_address=DISPATCH,
   thread_pointer=configuration.TP,thread_id=self.profile.get('thread_id',137),
   allocate=self.allocate,free=self.free,register_exit=self.register,read_clock=self.clock,
   get_tls=self.get_tls,initialize_registry=self.initialize,broadcast=self.broadcast,
   parse_decimal=self.decimal,get_auxval=self.aux,get_property=self.property,
   varuint_scratch_address=0x78001000,expression_scratch_address=0x78001008,custom_scratch_address=0x78001010)
  kw.update(changes or {});return bootstrap.run_elf_constructors(p,**kw)


def array_entries(args,p,base):
 with args.library.open('rb') as stream:
  section=ELFFile(stream).get_section_by_name('.init_array');address=section['sh_addr'];count=section['sh_size']//8
 assert count==13
 return tuple(int.from_bytes(_read_span(p,base+address+i*8,8),'little')-base for i in range(count))

def native_sequence(args,p,base,profile,sp,entries):
 services=Services(base,profile);saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[]
 pending_once=False;scopes=[];returns=[];repeat=len(entries)
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  exports={name:LIBC_BASE+elf.get_section_by_name('.dynsym').get_symbol_by_name(name)[0]['st_value']
   for name in ('strtol','pthread_cond_broadcast','memcmp','strncmp')}
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000)
  cpu.mem_map(ARENA,support.previous.ARENA_SIZE);cpus.append(cpu);return cpu
 def allocate(cpu,n):return services.allocate(None,n)
 def register(cpu):return services.register(None,*(reg(cpu,i) for i in range(3)))
 def clock(cpu):
  status,sec,ns=services.clock(None,reg(cpu,0))
  cpu.mem_write(reg(cpu,1),(sec&MASK64).to_bytes(8,'little')+ns.to_bytes(8,'little'));return status
 def decimal(cpu):
  services.events.append(('strtol',*(reg(cpu,i) for i in range(3))))
  cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports['strtol']);return None
 def memcmp(cpu):
  cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports['memcmp']);return None
 def property(cpu):
  address=reg(cpu,1);status=profile.get('property_status',0)
  if status>0:cpu.mem_write(address,bytes(cpu.mem_read(base+0x6EC1E,10)))
  services.events.append(('property',reg(cpu,0),address,status));return status
 def strncmp(cpu):
  cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports['strncmp']);return None
 def once(cpu):
  nonlocal pending_once
  assert reg(cpu,0)==base+0x3E31F8 and reg(cpu,1)==base+0x343980
  state=int.from_bytes(cpu.mem_read(base+0x3E31F8,4),'little')
  if state==0:
   cpu.mem_write(base+0x3E31F8,(1).to_bytes(4,'little'));pending_once=True
   cpu.reg_write(v.arm.UC_ARM64_REG_PC,base+0x343980);return None
  assert state==2;return 0
 def create(cpu):
  key=services.next_key;services.next_key+=1
  services.events.append(('key_create',reg(cpu,0),reg(cpu,1),key))
  cpu.mem_write(reg(cpu,0),key.to_bytes(4,'little'));return 0
 def setvalue(cpu):return services.setvalue(None,reg(cpu,0),reg(cpu,1))
 def realloc(cpu):
  old,n=reg(cpu,0),reg(cpu,1);a=allocate(cpu,n)
  cpu.mem_write(a,bytes(cpu.mem_read(old,min(services.sizes[old],n))));return a
 def broadcast(cpu):
  services.events.append(('broadcast',reg(cpu,0)))
  cpu.reg_write(v.arm.UC_ARM64_REG_PC,exports['pthread_cond_broadcast']);return None
 def syscall(cpu,number):
  assert number==98
  return services.wake(None,*(reg(cpu,i) for i in range(3)))
 def observe(cpu,address):
  nonlocal pending_once
  if pending_once and address==base+0x343818:
   cpu.mem_write(base+0x3E31F8,(2).to_bytes(4,'little'));pending_once=False
  if address==base+0x26C858:scopes.append(reg(cpu,0))
  if address==DISPATCH:
   assert cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
   returns.append(len(services.events));print('Original loader returned',hex(entries[len(returns)-1]),'services',len(services.events),'scopes',len(scopes),flush=True)
   if len(returns)==repeat:cpu.reg_write(v.arm.UC_ARM64_REG_PC,v.oracle.STOP)
   else:
    cpu.reg_write(v.arm.UC_ARM64_REG_X30,DISPATCH)
    cpu.reg_write(v.arm.UC_ARM64_REG_PC,base+entries[len(returns)])
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,entries[0],[],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347EA0:register,0x348450:clock,0x3484B0:decimal,0x348330:lambda c:services.aux(None,reg(c,0)),0x347FE0:memcmp,0x3486D0:property,0x348400:strncmp,
    0x3486B0:once,0x348620:create,0x3485D0:lambda c:services.get(None,reg(c,0)),
    0x348580:setvalue,0x348320:realloc,0x347FA0:lambda c:services.free(None,reg(c,0)),0x3485A0:broadcast},
   real_mutexes=True,real_diagnostics=True,real_recursive_mutexes=True,real_singletons=True,
   thread_id=profile.get('thread_id',137),syscall_handler=syscall,instruction_observer=observe,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_X30:DISPATCH},instruction_limit=120000000,
   code_hook_ranges=((DISPATCH,DISPATCH),(base+0x343818,base+0x343818),
    (base+0x26C858,base+0x26C858),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp and len(returns)==repeat
 return cpu,services,scopes,returns


def compare(args,base,profile,sp,label):
 source=configuration.fixture(args,base,profile);p=configuration.fixture(args,base,profile)
 assert source==p
 entries=array_entries(args,source,base)
 cpu,expected,scopes,returns=native_sequence(args,source,base,profile,sp,entries)
 services=Services(base,profile);result=services.sequence(p,sp)
 assert result.entries==entries and len(result.constructor_results)==13
 # Existing modules expose ordered logical frees; insert each complete
 # allocation/free stream at its first allocation in the shared plan.
 modules=[r for r in result.constructor_results if hasattr(r,'effects')]
 owners={e.address:i for i,r in enumerate(modules) for e in r.effects if e.kind=='allocate'}
 streams=[[(('allocate',e.size,e.address) if e.kind=='allocate' else ('free',e.address)) for e in r.effects] for r in modules]
 modeled=[];seen=set()
 for event in services.events:
  if event[0] not in ('allocate','free'):continue
  if event[0]=='allocate' and event[2] in owners:
   index=owners[event[2]]
   if index not in seen:modeled.extend(streams[index]);seen.add(index)
  else:modeled.append(event)
 assert modeled==[e for e in expected.events if e[0] in ('allocate','free')],(label,'allocation/free order')
 assert [e for e in services.events if e[0]=='atexit']==[e for e in expected.events if e[0]=='atexit'],(label,'registration order')
 assert [e for e in services.events if e[0] not in ('allocate','free','atexit')]==[e for e in expected.events if e[0] not in ('allocate','free','atexit')],(label,'OS/TLS/clock order')
 assert services.sizes==expected.sizes and services.specific==expected.specific
 assert list(result.constructor_results[9].diagnostic_scope_addresses)==scopes
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  if v.oracle.GUEST+0xA000<=page<<12<v.oracle.GUEST+0x10000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,constructors=13,original_service_count=len(expected.events),
  actual_diagnostic_scopes=len(scopes),module_publications=sum(len(r.publications) for r in modules),
  allocation_free_effect_count=len(modeled),registrations=sum(e[0]=='atexit' for e in expected.events),
  natural_all_13_returns_SP_verified=True,all_guest_heap_image_libc_pages_match=True,
  ordered_allocation_free_registration_and_OS_streams_match=True,shared_TLS_and_allocation_state_match=True,
  module_registration_allocation_interleaving_compared=False,physical_native_stack_compared=False,
  native_snapshot_input=False,fresh_independent_ELF_inputs=True)


def negatives(args):
 base=0x122C0000;initial=configuration.fixture(args,base,{});rows=[]
 def reject(label,changes=None,mutation=None):
  p={k:bytearray(data) for k,data in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()}
  try:Services(base,{}).sequence(p,v.SP,changes)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError('accepted sequence guard '+label)
  assert before=={k:bytes(data) for k,data in p.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_image',dict(image_base=base+1)),('unaligned_SP',dict(entry_stack_address=v.SP+1)),
  ('zero_return',dict(entry_return_address=0)),('zero_thread',dict(thread_id=0)),
  ('boolean_thread',dict(thread_id=True)),('unaligned_TP',dict(thread_pointer=configuration.TP+1)),
  ('node_budget',dict(max_nodes=0)),('code_budget',dict(max_code_words=0)),
  ('vector_budget',dict(max_vector_bytes=0)),('byte_budget',dict(max_bytes=0)),
  ('invalid_reserved',dict(reserved_regions=((2,1),))),
  ('scratch_alias',dict(expression_scratch_address=0x78001000)),
  ('scratch_frame',dict(varuint_scratch_address=v.SP-0x100)),
  ('scratch_image',dict(varuint_scratch_address=base+0x3D2000)),
  ('scratch_unmapped',dict(custom_scratch_address=0x76000000)),
  ('NULL_allocator',dict(allocate=lambda *a:0)),('unmapped_allocator',dict(allocate=lambda *a:0x76000000)),
  ('image_allocator',dict(allocate=lambda *a:base+0x3D2000)),
  ('frame_allocator',dict(allocate=lambda *a:v.SP-0x100)),
  ('scratch_allocator',dict(allocate=lambda *a:0x78001000)),
  ('TP_allocator',dict(allocate=lambda *a:configuration.TP)),
  ('reserved_heap',dict(reserved_regions=((ARENA,ARENA+configuration.support.previous.ARENA_SIZE),)))):
  reject(label,changes)
 for name in ('allocate','free','register_exit','read_clock','get_tls','initialize_registry','broadcast','parse_decimal','get_auxval'):
  reject('missing_'+name,{name:None})
 for index in (0,5,12):
  reject('unsupported_array_'+str(index),mutation=lambda p,i=index:_write_span(p,base+0x374CE0+i*8,bytes(8)))
 reject('reordered_array',mutation=lambda p:_write_span(p,base+0x374CE0,_read_span(p,base+0x374CE8,8)))
 reject('reserved_clock',dict(reserved_regions=((base+0x3D17C8,base+0x3D17D0),)))
 reject('retired_initializer_grammar',mutation=lambda p:_write_span(p,base+0x2DC408,bytes(4)))
 reject('retired_control_store_grammar',mutation=lambda p:_write_span(p,base+0x2DC874,bytes(4)))
 reject('retired_export_spill_grammar',mutation=lambda p:_write_span(p,base+0x32A9D4,bytes(4)))
 reject('late_aux_refusal',dict(get_auxval=lambda *a:(_ for _ in ()).throw(RefillUnsupported('aux refused'))))
 print('Loader sequence rollback guards',len(rows),'passed',flush=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 rows=[]
 for base,delta in ((0x122C0000,0),(0x775C205000,-0xC80)):
  for label,profile in (('complete_actual_ELF',{}),('complete_relocated_inputs',dict(allocation_delta=0xC00,thread_id=1,
    registration_status=0,time=(1791023800,123456789),auxval=256,property_status=10))):
   profile=dict(profile,padding=0xA5 if not delta else 0xFF,stack_padding=0 if not delta else 0x39)
   rows.append(compare(args,base,profile,v.SP+delta,label));print('Full loader',hex(base),label,'passed',flush=True)
 guards=negatives(args)
 evidence=dict(schema='vm9-elf-constructor-sequence-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_sequence_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=2,
  complete_init_array_sequence_implemented=True,all_13_original_constructors_executed=True,
  fresh_independent_ELF_inputs=True,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  full_ELF_binary_mapping_and_linking_verified=False,full_JNI_bootstrap_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Full constructor sequence controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
