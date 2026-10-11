"""Fresh full +2679f0 against independent relocated ELF inputs.

Execute original constructors, diagnostic scopes, matching-libc decimal and
mutex/condition code. Serialized allocation, TLS keys and futex are explicit
guest services. No original output becomes a Python input.
"""
from pathlib import Path
import argparse,hashlib,json,re
from elftools.elf.elffile import ELFFile
from verify_vm9_root_configuration import LIBC_BASE
import verify_vm9_elf_support_constructors_20261011 as support
import vm9_elf_bootstrap as bootstrap
import vm9_objects as objects
import vm9_registry as registry
from vm9_allocator import _read_span,_write_span,RefillUnsupported

v=support.v
ARENA=support.previous.ARENA
DISPATCH=v.oracle.GUEST+0x9000
TP=v.oracle.GUEST+0xD000
MASK64=(1<<64)-1
GLOBALS=((0x9D7EC,0x9D81C,0x3DECF4,0x3DECFC),
 (0x9D7BC,0x9D848,0x3DEC64,0x3DEC70),(0x9D7C8,0x9D83C,0x3DEC88,0x3DEC94),
 (0x9D7D4,0x9D830,0x3DECAC,0x3DECB8),(0x9D7E0,0x9D824,0x3DECD0,0x3DECDC))


def fixture(args,base,profile):
 p=support.previous.prepare(args,base,profile.get('padding',0xA5),profile.get('stack_padding',0))
 _write_span(p,TP+8,(v.oracle.GUEST+0xC000).to_bytes(8,'little'))
 _write_span(p,v.oracle.GUEST+0xC010,profile.get('thread_id',137).to_bytes(4,'little'))
 if profile.get('warm_globals'):
  for source,mask,destination,flag in GLOBALS:
   objects.decode_masked_bytes(p,source_address=base+source,mask_address=base+mask,destination_address=base+destination)
   _write_span(p,base+flag,(2).to_bytes(4,'little'))
 if profile.get('decimal_suffix'):
  adjustment=(int.from_bytes(_read_span(p,base+0x267CB0,4),'little')>>10)&4095
  _write_span(p,base+0x3DECF4,str(adjustment*4+3).encode()+b'\0')
  _write_span(p,base+0x3DECFC,(9).to_bytes(4,'little'))
 if profile.get('redirect_templates'):
  pc=base+0x267444
  index=(((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF421C8D4)&MASK64
  for i,offset in enumerate((0,0x30,0x48,0x18)):
   address=v.oracle.GUEST+0x6000+i*32
   _write_span(p,address,bytes([0x31+i])*16)
   _write_span(p,base+0x3822F8+offset,((address-index)&MASK64).to_bytes(8,'little'))
 if profile.get('redirect_markers'):
  for offset,immediate in ((0x26791C,0x1234),(0x267924,0x5678),(0x267944,0x2345),(0x267948,0x6789)):
   word=int.from_bytes(_read_span(p,base+offset,4),'little')
   _write_span(p,base+offset,((word&~(65535<<5))|(immediate<<5)).to_bytes(4,'little'))
 return p


class Services:
 def __init__(self,base,profile):
  self.base=base;self.profile=profile;self.cursor=ARENA+profile.get('allocation_delta',0)
  self.events=[];self.sizes={};self.specific={};self.next_key=9

 def allocate(self,p,n):
  a=self.cursor;self.cursor+=(max(n,1)+15)&~15
  assert self.cursor<=ARENA+support.previous.ARENA_SIZE
  self.sizes[a]=n;self.events.append(('allocate',n,a));return a

 def free(self,p,a):self.events.append(('free',a));return 0

 def realloc(self,p,a,n):
  b=self.allocate(p,n);_write_span(p,b,_read_span(p,a,min(self.sizes[a],n)));return b

 def get(self,p,key):self.events.append(('getspecific',key));return self.specific.get(key,0)

 def setvalue(self,p,key,value):
  self.events.append(('setspecific',key,value));self.specific[key]=value;return 0

 def create(self,p,address,fn):
  key=self.next_key;self.next_key+=1
  self.events.append(('key_create',address,fn,key));_write_span(p,address,key.to_bytes(4,'little'));return 0

 def register(self,p,fn,obj,dso):
  status=self.profile.get('registration_status',7)
  self.events.append(('atexit',fn,obj,dso,status));return status

 def clock(self,p,key):
  sec,ns=self.profile.get('time',(123,987654321))
  self.events.append(('clock',key,sec,ns));return 0,sec,ns

 def get_tls(self,p,control):
  return objects.get_emulated_tls_address(p,control_address=control,image_base=self.base,
   allocate=self.allocate,reallocate=self.realloc,get_specific=self.get,set_specific=self.setvalue,
   create_key=self.create,once_wake=lambda *a:0)

 def destructor(self,p,fn,obj,dso):
  return objects.register_emulated_thread_destructor(p,destructor_address=fn,object_address=obj,
   image_base=self.base,allocate=self.allocate,get_tls=self.get_tls,create_key=self.create,
   set_specific=self.setvalue,register_atexit=self.register,thread_id=self.profile.get('thread_id',137))

 def initialize(self,p):
  return objects.initialize_scoped_tls_registry(p,image_base=self.base,get_tls=self.get_tls,register_destructor=self.destructor)

 def wake(self,p,address,operation,count):
  self.events.append(('wake',address,operation,count));return 0

 def broadcast(self,p,address):
  self.events.append(('broadcast',address))
  return objects.broadcast_condition_no_waiters(p,condition_address=address,wake=self.wake)

 def decimal(self,p,address):
  self.events.append(('strtol',address,0,10))
  match=re.match(rb'\s*([+-]?[0-9]+)',objects._cstring(p,address,24))
  value=int(match.group(1)) if match else 0
  return min((1<<63)-1,max(-(1<<63),value))

 def run(self,p,sp,changes=None):
  kw=dict(image_base=self.base,entry_stack_address=sp,thread_pointer=TP,
   thread_id=self.profile.get('thread_id',137),allocate=self.allocate,free=self.free,
   read_clock=self.clock,get_tls=self.get_tls,initialize_registry=self.initialize,
   broadcast=self.broadcast,parse_decimal=self.decimal)
  kw.update(changes or {})
  return bootstrap.run_configuration_constructor(p,**kw)


def native(args,p,base,profile,sp):
 services=Services(base,profile);saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[]
 pending_once=False;scopes=[];returns=[];repeat=profile.get('repeat',1)
 with args.libc.open('rb') as stream:
  elf=ELFFile(stream)
  exports={name:LIBC_BASE+elf.get_section_by_name('.dynsym').get_symbol_by_name(name)[0]['st_value']
   for name in ('strtol','pthread_cond_broadcast')}
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
   returns.append(len(services.events))
   if len(returns)==repeat:cpu.reg_write(v.arm.UC_ARM64_REG_PC,v.oracle.STOP)
   else:
    cpu.reg_write(v.arm.UC_ARM64_REG_X30,DISPATCH)
    cpu.reg_write(v.arm.UC_ARM64_REG_PC,base+0x2679F0)
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,0x2679F0,[],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347EA0:register,0x348450:clock,0x3484B0:decimal,
    0x3486B0:once,0x348620:create,0x3485D0:lambda c:services.get(None,reg(c,0)),
    0x348580:setvalue,0x348320:realloc,0x347FA0:lambda c:services.free(None,reg(c,0)),0x3485A0:broadcast},
   real_mutexes=True,real_diagnostics=True,real_recursive_mutexes=True,real_singletons=True,
   thread_id=profile.get('thread_id',137),syscall_handler=syscall,instruction_observer=observe,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_X30:DISPATCH},instruction_limit=1000000,
   code_hook_ranges=((DISPATCH,DISPATCH),(base+0x343818,base+0x343818),
    (base+0x26C858,base+0x26C858),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp and len(returns)==repeat
 return cpu,services,scopes,returns


def compare(args,base,label,profile,sp):
 source=fixture(args,base,profile);p=fixture(args,base,profile)
 assert source==p
 cpu,expected,scopes,returns=native(args,source,base,profile,sp)
 services=Services(base,profile);results=[];boundaries=[]
 for _ in range(profile.get('repeat',1)):
  results.append(services.run(p,sp));boundaries.append(len(services.events))
 assert services.events==expected.events,(label,'ordered services')
 assert boundaries==returns and services.specific==expected.specific and services.sizes==expected.sizes
 assert [s for r in results for s in r.diagnostic_scope_addresses]==scopes
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  if v.oracle.GUEST+0xA000<=page<<12<v.oracle.GUEST+0x10000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,constructor_returns=len(results),service_count=len(services.events),
  actual_diagnostic_scopes=len(scopes),cold_scope_count=2,warm_scope_count=0 if len(results)>1 else None,
  natural_return_SP_verified=True,all_guest_heap_image_libc_pages_match=True,
  ordered_services_TLS_allocations_and_boundaries_match=True,actual_diagnostic_scope_addresses_match=True,
  fresh_independent_ELF_inputs=True,native_snapshot_input=False,physical_native_stack_compared=False)


def negatives(args):
 base=0x122C0000;initial=fixture(args,base,{});rows=[]
 def reject(label,changes=None,mutation=None,fault=None,warm=False):
  p={k:bytearray(data) for k,data in initial.items()}
  services=Services(base,{})
  if warm:services.run(p,v.SP)
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=bootstrap._write_span;hits=[]
  def write(staged,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected configuration publication failure')
   return saved(staged,address,data)
  try:
   if fault:bootstrap._write_span=write
   try:services.run(p,v.SP,changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted '+label)
  finally:bootstrap._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('boolean_image',dict(image_base=True)),('unaligned_image',dict(image_base=base+1)),
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('low_SP',dict(entry_stack_address=0x1000)),
  ('unaligned_TP',dict(thread_pointer=TP+1)),('zero_thread',dict(thread_id=0)),
  ('boolean_thread',dict(thread_id=True)),('overflow_thread',dict(thread_id=1<<32)),
  ('node_budget',dict(max_nodes=0)),('byte_budget',dict(max_bytes=0)),
  ('invalid_reserved',dict(reserved_regions=((2,1),))),
  ('NULL_allocator',dict(allocate=lambda *a:0)),('unmapped_allocator',dict(allocate=lambda *a:0x76000000)),
  ('image_allocator',dict(allocate=lambda *a:base+0x3D2000)),('frame_allocator',dict(allocate=lambda *a:v.SP-0x100)),
  ('reused_allocator',dict(allocate=lambda *a:ARENA)),
  ('overflow_decimal',dict(parse_decimal=lambda *a:1<<63)),('boolean_decimal',dict(parse_decimal=lambda *a:True)),
  ('alternate_dispatch',dict(parse_decimal=lambda *a:0)),
  ('late_free_refusal',dict(free=lambda *a:(_ for _ in ()).throw(RefillUnsupported('free refused')))),
  ('late_clock_refusal',dict(read_clock=lambda *a:(_ for _ in ()).throw(RefillUnsupported('clock refused'))))):reject(label,changes)
 for name in ('allocate','free','read_clock','get_tls','initialize_registry','broadcast','parse_decimal'):
  reject('missing_'+name,{name:None})
 for slot in (0x267CB0,0x26791C,0x267924,0x267944,0x267948):
  reject('instruction_grammar_'+hex(slot),mutation=lambda p,s=slot:_write_span(p,base+s,bytes(4)))
 reject('unmapped_template',mutation=lambda p:_write_span(p,base+0x3822F8,bytes(8)))
 for slot in (8,0x10,0x20,0x28,0x38,0x40,0x50,0x58,0x60):
  reject('unsupported_global_selector_'+hex(slot),mutation=lambda p,s=slot:_write_span(p,base+0x3822F8+s,bytes(8)))
 reject('unterminated_mask',mutation=lambda p:_write_span(p,base+0x9D81C,b'\1'*25))
 for slot,width in ((0x3DECFC,4),(0x3DEC74,16),(0x3DECA8,4),(0x3D1680,8),(0x3D1558,8),
                    (0x3DEDA0,8),(0x3DEDA8,8),(0x3E31F8,4)):
  reject('reserved_'+hex(slot),dict(reserved_regions=((base+slot,base+slot+width),)))
 for slot in (0x3DECFC,0x3DEC74,0x3DECCC,0x3DECA8):
  reject('write_failure_'+hex(slot),fault=lambda a,d,s=slot:a==base+s)
 reject('reserved_frame',dict(reserved_regions=((v.SP-0x1000,v.SP),)))
 reject('reserved_heap',dict(reserved_regions=((ARENA,ARENA+support.previous.ARENA_SIZE),)))
 for guard in (0x3D1680,0x3D1558,0x3DEDA0):
  reject('pending_guard_'+hex(guard),mutation=lambda p,g=guard:_write_span(p,base+g,b'\0\2'+bytes(6)))
 reject('diagnostic_bad_pthread',mutation=lambda p:_write_span(p,TP+8,bytes(8)))
 for field in (0x10,0x18):
  def bound(p,field=field):
   wrapper=int.from_bytes(_read_span(p,base+0x3D1678,8),'little')
   payload=int.from_bytes(_read_span(p,wrapper,8),'little')
   _write_span(p,payload+field,(1).to_bytes(8,'little'))
  reject('nonzero_copy_bound_'+hex(field),mutation=bound,warm=True)
 for name in ('construct_registry320','get_registry320_reference','construct_singleton136','get_singleton136_reference'):
  for service in (False,lambda *a:7):
   p={k:bytearray(data) for k,data in initial.items()};s=Services(base,{})
   kw=dict(image_base=base,entry_stack_address=v.SP,allocate=s.allocate,free=s.free,
    read_clock=s.clock,get_tls=s.get_tls,initialize_registry=s.initialize,broadcast=s.broadcast,
    diagnostic_scope=service)
   if not name.startswith('get_'):kw['object_address']=s.allocate(p,320 if 'registry' in name else 136)
   if name!='construct_registry320':kw['thread_id']=137
   before={k:bytes(data) for k,data in p.items()}
   try:getattr(registry,name)(p,**kw)
   except RefillUnsupported:pass
   else:raise AssertionError('invalid diagnostic contract accepted '+name)
   assert before=={k:bytes(data) for k,data in p.items()}
   rows.append(dict(label=name+('_noncallable' if service is False else '_invalid_return'),
    rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 print('Configuration rollback guards',len(rows),'passed',flush=True)
 return rows


PROFILES=[('cold',{}),('cold_then_two_warm',dict(repeat=3)),('warm_masked_globals',dict(warm_globals=True)),
 ('decimal_same_dispatch',dict(decimal_suffix=True)),('redirected_templates',dict(redirect_templates=True)),
 ('redirected_markers',dict(redirect_markers=True)),
 ('alternate_allocation_thread',dict(allocation_delta=0xC00,thread_id=1,registration_status=0)),
 ('alternate_clock',dict(time=(1791023800,123456789)))]


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
   rows.append(compare(args,base,label,profile,v.SP+delta))
   print('Configuration',hex(base),label,'passed',flush=True)
 evidence=dict(schema='vm9-elf-configuration-constructor-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=2,
  configuration_constructor_implemented=True,actual_diagnostic_scopes_executed=True,
  fresh_independent_ELF_inputs=True,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  full_ELF_loader_verified=False,full_JNI_bootstrap_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Configuration controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
