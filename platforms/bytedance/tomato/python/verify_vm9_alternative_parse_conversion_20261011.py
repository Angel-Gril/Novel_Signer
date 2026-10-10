"""Fresh B parse conversion, cold catalog, owned layouts and serial services.

AST and constructor formats come from independent Python and fresh ELF inputs.
Native snapshots are assertions only. Names and payloads are never published.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import verify_vm9_alternative_ast_module_segments_custom_20261011 as module
import verify_vm9_alternative_parse_codec_20261011 as codec
from vm9_allocator import _read_span,_write_span,RefillUnsupported
v=module

def native(args,base,pages,ast,*,stack_padding=0,entry_sp=0x781FF000,allocation_start=0x79000000,thread_id=137):
 p={k:bytearray(v) for k,v in pages.items()};oracle=module.heap.oracle
 with args.library.open('rb') as stream:
  elf=ELFFile(stream)
  for section in elf.iter_sections():
   if section['sh_type']!='SHT_RELA':continue
   symbols=elf.get_section(section['sh_link'])
   for relocation in section.iter_relocations():
    symbol=symbols.get_symbol(relocation['r_info_sym']);target={'memcpy':0x347F60,'memset':0x347F20,'strlen':0x347F40}.get(symbol.name)
    if relocation['r_info_type']==257 and target is not None:
     assert symbol['st_shndx']=='SHN_UNDEF' and relocation['r_addend']==0
     _write_span(p,base+relocation['r_offset'],(base+target).to_bytes(8,'little'))
 codec_pair,destination,aux=(oracle.GUEST+n for n in (0xB000,0xB100,0xB200))
 for address,size in ((codec_pair,16),(destination,128),(aux,24)):_write_span(p,address,bytes(size))
 table=oracle.GUEST+0xC048;count=3
 for index,case in enumerate(codec.actual_fixtures(args.library)[::33]):
  tag,rotation,key,fields=case['source'];pointer=oracle.GUEST+0xC200+index*64
  _write_span(p,pointer,bytes(value for field in fields for value in field))
  record=table+index*24;_write_span(p,record,bytes([tag,rotation,key]))
  _write_span(p,record+8,pointer.to_bytes(8,'little'))
  _write_span(p,record+16,len(fields).to_bytes(4,'little'))
 _write_span(p,codec_pair,table.to_bytes(8,'little')+count.to_bytes(8,'little'))
 saved=oracle.Uc,oracle.GUEST_SIZE;cpus=[];allocations=[];frees=[];registrations=[];frames=[];effects=[];pointer=allocation_start
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_write(0x78000000,bytes([stack_padding])*0x200000)
  cpu.mem_map(allocation_start,0x200000);cpu.mem_write(allocation_start,b'\xa5'*0x200000);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  nonlocal pointer
  address=pointer;pointer+=(max(size,1)+15)&~15;assert pointer<=allocation_start+0x200000
  allocations.append((address,size));effects.append(('allocate',address,size,bytes(cpu.mem_read(destination,128))));return address
 def free(cpu):
  address=cpu.reg_read(arm.UC_ARM64_REG_X0);frees.append(address)
  size=next(n for a,n in allocations if a==address)
  effects.append(('free',address,size,bytes(cpu.mem_read(destination,128))));return 0
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return thread_id
 def register(cpu):registrations.append([cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]);return 0
 def memcmp(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,module.heap.libc_memcmp(args.libc));return None
 sites=(0x2CD5A4,0x2AB500,0x2AB690,0x2DB55C,0x2DB6AC,0x2DB5E0,0x2DAB00,0x2DA9E0)
 def observe(cpu,address):
  off=address-base
  if off in sites:
   sp=cpu.reg_read(arm.UC_ARM64_REG_SP);frame=dict(offset=hex(off),SP=hex(sp),arguments=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4)])
   if off==0x2AB500:frame['initial_constructor_frame']=bytes(cpu.mem_read(sp-0x68,72)).hex()
   if off==0x2AB690:frame['constructor_records']=bytes(cpu.mem_read(sp+8,72)).hex()
   frames.append(frame)
 try:
  oracle.Uc=factory;oracle.GUEST_SIZE=max(saved[1],0x160000)
  for address in range(oracle.GUEST,oracle.GUEST+oracle.GUEST_SIZE,4096):p.setdefault(address>>12,bytearray(b'\xa5'*4096))
  status,_,_,_=oracle.native(args.library,base,0x2CD5A4,[codec_pair,ast,destination,aux],p,libc=args.libc,
   malloc_handler=allocate,host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},
   instruction_observer=observe,real_mutexes=True,extra_registers={arm.UC_ARM64_REG_SP:entry_sp},instruction_limit=12000000,
   code_hook_ranges=tuple((base+off,base+off) for off in sites)+((base+0x347E00,base+0x348800),))
 finally:oracle.Uc,oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==entry_sp
 result=dict(status=status,allocations=allocations,frees=frees,registrations=registrations,frames=frames,
  converted_hex=bytes(cpu.mem_read(destination,128)).hex(),aux_hex=bytes(cpu.mem_read(aux,24)).hex(),
  allocated_bytes=[dict(address=hex(a),size=n,hex=bytes(cpu.mem_read(a,n)).hex()) for a,n in allocations],
  globals=[dict(address=hex(base+off),hex=bytes(cpu.mem_read(base+off,size)).hex()) for off,size in ((0x3E2530,0xD0),(0x3E2750,0x30))],
  native_snapshot_input=False,stack_padding=stack_padding,entry_sp=hex(entry_sp))
 return result,cpu,p,effects


def compare(args,base,pages,ast,label,*,pad=0,sp=0x781FF000,thread_id=137):
 observed,cpu,p,effects=native(args,base,pages,ast,stack_padding=pad,entry_sp=sp,thread_id=thread_id)
 for address in range(0x78000000,0x78200000,4096):p[address>>12]=bytearray(bytes([pad])*4096)
 for address in range(0x79000000,0x79200000,4096):p[address>>12]=bytearray(b'\xa5'*4096)
 pointer=0x79000000;calls=[]
 def allocate(size):
  nonlocal pointer
  address=pointer;pointer+=(max(size,1)+15)&~15;calls.append((address,size));return address
 result=v.alternative.run_parser_conversion(p,image_base=base,ast_address=ast,
  codec_pair_address=v.heap.oracle.GUEST+0xB000,output_address=v.heap.oracle.GUEST+0xB100,
  error_address=v.heap.oracle.GUEST+0xB200,entry_stack_address=sp,thread_id=thread_id,allocate=allocate)
 assert result.status==observed['status'],(label,'status')
 assert [(e.kind,e.address,e.size,e.owner_bytes) for e in result.effects]==effects,(label,'ordered effects')
 assert calls==observed['allocations'],(label,'allocations',calls[:8],observed['allocations'][:8])
 assert [e.address for e in result.effects if e.kind=='free']==observed['frees'],(label,'frees')
 assert list(map(list,result.finalizers))==observed['registrations'],(label,'finalizers')
 for start,size in ((v.heap.oracle.GUEST,0x160000),(0x79000000,0x200000)):
  expected=bytes(cpu.mem_read(start,size));actual=_read_span(p,start,size)
  differences=[] if actual==expected else [(hex(start+i),a,b) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b]
  assert not differences,(label,'guest/heap',len(differences),differences[:16])
 differences=[]
 for page,data in p.items():
  address=page<<12
  if base<=address<base+0x400000:
   expected=bytes(cpu.mem_read(address,4096))
   if bytes(data)!=expected:differences.extend((hex(address+i-base),a,b) for i,(a,b) in enumerate(zip(data,expected)) if a!=b)
 assert not differences,(label,'image',len(differences),differences[:24])
 row=dict(label=label,base=hex(base),status=result.status,allocations=len(calls),free_count=len(observed['frees']),
  decoded_words=result.decoded_word_count,functions=result.function_count,stack_padding=pad,entry_sp=hex(sp),
  complete_guest_extra_2MiB_and_image_pages_match=True,native_snapshot_input=False,thread_id=thread_id,ordered_effects_and_finalizers_match=True)
 return row


def fixtures():
 code=v.previous.previous.code;cases=[]
 cases.append(v.previous.spec('empty',large_arena=True))
 for kind in range(4):
  for length in (0,1,22,23,47):
   cases.append(v.previous.spec(f'import_{kind}_{length}',imports=[v.previous.imported(kind,length)],
    globals_=[code.previous.entry(0x7E,1,[(3,7)])] if kind==3 else [],large_arena=True))
 for length in (0,1,22,23,47):
  cases.append(v.previous.spec('defined_export_'+str(length),[(b'e'*length,0,0)],definitions=[([],[])],functions=[0],
   bodies=[code.body([0x12345678,0xABCDEF01])],large_arena=True))
 cases.append(v.previous.spec('global_mismatch',imports=[v.previous.imported(3)],large_arena=True))
 cases.append(v.spec('data',v.previous.section(11,b'\2'+v.segments.data(1,payload=b'abc')+v.segments.data(0,payload=b'de')),data=True))
 for kind in (1,2,3):
  for length in (0,23):
   cases.append(v.previous.spec(f'ignored_export_{kind}_{length}',[(b'e'*length,kind,0)],imports=[v.previous.imported(kind,23)],
    globals_=[code.previous.entry(0x7E,1,[(3,7)])] if kind==3 else [],large_arena=True))
 for lengths in ((1,23,47,2,100,0),(63,23,22,128,255),(0,0,0)):
  cases.append(v.previous.spec('reassign_'+'_'.join(map(str,lengths)),[(bytes([97+i])*n,0,0) for i,n in enumerate(lengths)],
   definitions=[([],[])],functions=[0],bodies=[code.body([0,1,0xFFFFFFFF])],large_arena=True))
 for kinds in ((0,1,2,3),(3,2,1,0),(0,0),(3,3)):
  cases.append(v.previous.spec('mixed_'+''.join(map(str,kinds)),[(b'entry',0,kinds.count(0))],
   imports=[v.previous.imported(k,23) for k in kinds],definitions=[([0x7F],[0x7E])],functions=[0,0],
   bodies=[code.body(),code.body([0x12345678,0x9ABCDEF0],7,[(3,-2)])],
   globals_=[code.previous.entry(0x7E,1,[(3,0xFFFFFFFF)]) for k in kinds if k==3],large_arena=True))
 for value,mutable,op in ((0x7F,0,2),(0x7E,1,3),(0x7D,0,4),(0x7C,1,5)):
  cases.append(v.previous.spec(f'global_value_{value}_{mutable}',imports=[(b'm',b'f',3,bytes([value,mutable]))],
   globals_=[code.previous.entry(value,mutable,[(op,0xFFFFFFFF)])],large_arena=True))
 for imported,defined in ((0,1),(1,2),(2,1)):
  cases.append(v.previous.spec(f'global_mismatch_{imported}_{defined}',imports=[v.previous.imported(3)]*imported,
   globals_=[code.previous.entry(0x7E,1,[(3,7)])]*defined,large_arena=True))
 for count in (0,1,2):
  cases.append(v.previous.spec('unexported_'+str(count),definitions=[([],[])],functions=[0]*count,
   bodies=[code.body([0xAABBCCDD]) for _ in range(count)],large_arena=True))
 for flags in (0,1,2,3):
  cases.append(v.spec('data_flags_'+str(flags),v.previous.section(11,b'\1'+v.segments.data(flags,index=7,
   expression=b'\x41\7\x0b',payload=b'payload')),data=True))
 for index in (1,0xFFFFFFFF):
  cases.append(v.previous.spec('invalid_export_'+str(index),[(b'e'*23,0,0)],definitions=[([],[])],functions=[0],
   bodies=[code.body()],large_arena=True,converted_export_index=index))
 case=v.previous.spec('start',definitions=[([],[])],functions=[0],bodies=[code.body()],large_arena=True)
 marker=v.previous.section(10,b'\1'+code.body()['blob']);offset=case['blob'].rfind(marker);assert offset>=8
 case['blob']=case['blob'][:offset]+v.previous.section(8,b'\0')+case['blob'][offset:];cases.append(case)
 case=v.previous.spec('warm_catalog',definitions=[([],[])],functions=[0,0],bodies=[code.body([7]),code.body([19])],large_arena=True,warm_catalog=True)
 cases.append(case)
 return cases


def prepare_case(args,base,case):
 p,result,_=v.previous.model(args,base,case,**v.options(case));assert result.status==0
 if 'converted_export_index' in case:
  entry=int.from_bytes(_read_span(p,v.layout.OUT+0xA8,8),'little')
  _write_span(p,entry+32,case['converted_export_index'].to_bytes(4,'little'))
 if case.get('warm_catalog'):
  table=v.heap.oracle.GUEST+0x110000;p[table>>12]=bytearray(4096)
  for index,fixture in enumerate(codec.actual_fixtures(args.library)[::33]):
   tag,rotation,key,fields=fixture['target'];pointer=base+(0x3E25B0,0x3E2570,0x3E2530)[index]
   _write_span(p,pointer,bytes(value for field in fields for value in field))
   _write_span(p,table+24*index,bytes([tag,rotation,key])+bytes(5)+pointer.to_bytes(8,'little')+len(fields).to_bytes(8,'little'))
  for offset in (0x3E2548,0x3E2550,0x3E2558,0x3E2560,0x3E2568):_write_span(p,base+offset,(0x101|(137<<32)).to_bytes(8,'little'))
  _write_span(p,base+0x3E2580,table.to_bytes(8,'little')+(3).to_bytes(8,'little'))
  _write_span(p,base+0x3E25E0,table.to_bytes(8,'little')+(table+72).to_bytes(8,'little')*2)
 return p


def negatives(args):
 rows=[];base=v.BASES[0];case=next(c for c in fixtures() if c['label']=='defined_export_1')
 with v.arena(case):
  ast_pages=prepare_case(args,base,case)
  _,_,initial,_=native(args,base,ast_pages,v.layout.OUT)
 for address in range(0x78000000,0x78200000,4096):initial[address>>12]=bytearray(4096)
 for address in range(0x79000000,0x79200000,4096):initial[address>>12]=bytearray(b'\xa5'*4096)
 def reject(label,changes=None,mutate=None,fault=None):
  p={k:bytearray(v) for k,v in initial.items()};pointer=0x79000000
  def allocate(size):
   nonlocal pointer
   out=pointer;pointer+=(max(size,1)+15)&~15;return out
  params=dict(image_base=base,ast_address=v.layout.OUT,codec_pair_address=v.heap.oracle.GUEST+0xB000,
   output_address=v.heap.oracle.GUEST+0xB100,error_address=v.heap.oracle.GUEST+0xB200,
   entry_stack_address=0x781FF000,thread_id=137,allocate=allocate)
  params.update(changes or {})
  if mutate:mutate(p)
  before={k:bytes(value) for k,value in p.items()};saved=v.alternative._write_span;hits=[]
  def write(current,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected conversion write failure')
   return saved(current,address,data)
  try:
   if fault:v.alternative._write_span=write
   try:v.alternative.run_parser_conversion(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('guard accepted '+label)
  finally:v.alternative._write_span=saved
  assert before=={k:bytes(value) for k,value in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
 for label,change in (
   ('unaligned_SP',dict(entry_stack_address=0x781FF001)),('boolean_SP',dict(entry_stack_address=True)),
   ('zero_thread',dict(thread_id=0)),('negative_thread',dict(thread_id=-1)),('boolean_thread',dict(thread_id=True)),
   ('thread_overflow',dict(thread_id=1<<31)),('word_budget',dict(max_code_words=1)),('boolean_word_budget',dict(max_code_words=True)),
   ('node_budget',dict(max_nodes=1)),('byte_budget',dict(max_vector_bytes=63)),
   ('missing_allocator',dict(allocate=None)),('allocator_alias',dict(allocate=lambda n:v.layout.OUT)),
   ('allocator_unmapped',dict(allocate=lambda n:0x76000000)),('output_alias',dict(output_address=v.layout.OUT)),
   ('unmapped_SP',dict(entry_stack_address=0x76010000)),('temporary_overlap',dict(entry_stack_address=v.layout.OUT+0xAB0))):reject(label,change)
 reject('dirty_output',mutate=lambda p:_write_span(p,v.heap.oracle.GUEST+0xB100,b'\1'))
 reject('dirty_error',mutate=lambda p:_write_span(p,v.heap.oracle.GUEST+0xB200,b'\1'))
 reject('busy_catalog',mutate=lambda p:_write_span(p,base+0x3E2560,(2).to_bytes(8,'little')))
 reject('zero_codec_abort',mutate=lambda p:_write_span(p,v.heap.oracle.GUEST+0xB008,bytes(8)))
 reject('codec_fields_budget',mutate=lambda p:_write_span(p,v.heap.oracle.GUEST+0xC058,(1025).to_bytes(4,'little')))
 def raw_invalid(p):
  node=int.from_bytes(_read_span(p,v.layout.OUT+0x30,8),'little');_write_span(p,node+0x70,(0xFFFFFFFF).to_bytes(4,'little'))
 reject('raw_range_capacity',mutate=raw_invalid)
 reject('catalog_copy_failure',fault=lambda a,d:a==base+0x3E25E0)
 reject('function_publication_failure',fault=lambda a,d:a==v.heap.oracle.GUEST+0xB110)
 reject('late_instruction_failure',fault=lambda a,d:len(d)==10 and a>=0x79000000+64+80+12)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.heap.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.heap.LIBC_HASH
 cases=fixtures();rows=[];guards=negatives(args)
 for base in v.BASES:
  for index,case in enumerate(cases,1):
   with v.arena(case):
    p=prepare_case(args,base,case);rows.append(compare(args,base,p,v.layout.OUT,case['label']))
   if index%12==0:print('B parse',hex(base),index,'/',len(cases),'passed',flush=True)
  for label in ('mixed_0123','unexported_2','reassign_1_23_47_2_100_0'):
   case=next(c for c in cases if c['label']==label)
   with v.arena(case):
    p=prepare_case(args,base,case)
    for pad in (0x39,0xA5,0xFF):rows.append(compare(args,base,p,v.layout.OUT,label+'_pad_'+str(pad),pad=pad))
    for delta in (-0xC80,0x100):rows.append(compare(args,base,p,v.layout.OUT,label+'_SP_'+str(delta),sp=0x781FF000+delta))
    for tid in (1,0x12345678):rows.append(compare(args,base,p,v.layout.OUT,label+'_tid_'+str(tid),thread_id=tid))
  case=v.actual_specs(args.library)[-1]
  with v.arena(case):
   p=prepare_case(args,base,case)
   for pad in (0,0xA5):
    row=compare(args,base,p,v.layout.OUT,'complete_actual_ELF_'+str(pad),pad=pad)
    assert row['decoded_words']==54533 and row['functions']==139 and row['allocations']==128
    row['actual_ELF_complete_module']=True;rows.append(row)
   print('B parse',hex(base),'complete actual ELF passed twice',flush=True)
  with v.previous.previous.previous.definitions.guest_layout(0x7000000000):
   for label in ('defined_export_1','mixed_0123','data'):
    case=next(c for c in cases if c['label']==label)
    with v.arena(case):
     p=prepare_case(args,base,case);rows.append(compare(args,base,p,v.layout.OUT,label+'_high_guest'))
 evidence=dict(schema='vm9-alternative-parse-conversion-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=v.heap.LIBC_HASH,
  native_Python_parse_conversion_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=12,
  complete_actual_ELF_module_controls=4,relocated_entry_stack_controls=12,nonzero_stack_padding_controls=20,alternate_thread_id_controls=12,relocated_full_guest_controls=6,
  native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('B parse conversion',len(rows),'native/Python',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
