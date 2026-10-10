"""Fresh native converted-module cleanup over independent Python parse inputs.

Checks complete owned bytes and ordered frees; native snapshots are assertions.
Private names and payloads are never exported.
"""
from pathlib import Path
from dataclasses import replace
import argparse,hashlib,json
import verify_vm9_alternative_parse_conversion_20261011 as parse
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from unicorn import arm64_const as arm
v=parse.v;oracle=v.heap.oracle

def prepare(args,base,case,*,padding=0):
 p=parse.prepare_case(args,base,case)
 for start,size,fill in ((oracle.GUEST,0x160000,0xA5),(0x78000000,0x200000,padding),(0x79000000,0x200000,0xA5)):
  for address in range(start,start+size,4096):p.setdefault(address>>12,bytearray(bytes([fill])*4096))
 pair,destination,error=(oracle.GUEST+n for n in (0xB000,0xB100,0xB200))
 for address,size in ((pair,16),(destination,128),(error,24)):_write_span(p,address,bytes(size))
 table=oracle.GUEST+0xC048
 for index,case_codec in enumerate(parse.codec.actual_fixtures(args.library)[::33]):
  tag,rotation,key,fields=case_codec['source'];pointer=oracle.GUEST+0xC200+index*64
  _write_span(p,pointer,bytes(value for field in fields for value in field))
  record=table+index*24;_write_span(p,record,bytes([tag,rotation,key]))
  _write_span(p,record+8,pointer.to_bytes(8,'little'));_write_span(p,record+16,len(fields).to_bytes(4,'little'))
 _write_span(p,pair,table.to_bytes(8,'little')+(3).to_bytes(8,'little'))
 pointer=0x79000000
 def allocate(size):
  nonlocal pointer
  address=pointer;pointer+=(size+15)&~15;assert pointer<=0x79200000;return address
 result=v.alternative.run_parser_conversion(p,image_base=base,ast_address=v.layout.OUT,
  codec_pair_address=pair,output_address=destination,error_address=error,entry_stack_address=0x781FF000,
  thread_id=137,allocate=allocate)
 return p,result

def native(args,base,pages,*,entry_sp=0x781FF000):
 saved=oracle.Uc,oracle.GUEST_SIZE;cpus=[];effects=[];destination=oracle.GUEST+0xB100
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(0x79000000,0x200000);cpus.append(cpu);return cpu
 def free(cpu):
  address=cpu.reg_read(arm.UC_ARM64_REG_X0)
  effects.append((address,bytes(cpu.mem_read(destination,128))));return 0
 try:
  oracle.Uc=factory;oracle.GUEST_SIZE=0x160000
  oracle.native(args.library,base,0x2CB968,[destination],pages,host_imports={0x347FA0:free},
   extra_registers={arm.UC_ARM64_REG_SP:entry_sp},instruction_limit=1000000)
 finally:oracle.Uc,oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==entry_sp
 return cpu,effects

def compare(args,base,pages,parsed,label,*,entry_sp=0x781FF000):
 cpu,expected=native(args,base,pages,entry_sp=entry_sp)
 current={k:bytearray(value) for k,value in pages.items()}
 result=v.alternative.cleanup_parser_conversion(current,image_base=base,output_address=oracle.GUEST+0xB100)
 assert [(e.address,e.owner_bytes) for e in result.effects]==expected,(label,'effects')
 allocations={e.address:e.size for e in parsed.effects if e.kind=='allocate'}
 assert all(e.kind=='free' and e.size==allocations[e.address] for e in result.effects),(label,'free sizes')
 assert len({e.address for e in result.effects})==len(result.effects)
 for start,size in ((oracle.GUEST,0x160000),(0x79000000,0x200000)):
  actual=_read_span(current,start,size);wanted=bytes(cpu.mem_read(start,size))
  assert actual==wanted,(label,hex(start),'guest/heap',[(hex(start+i),a,b) for i,(a,b) in enumerate(zip(actual,wanted)) if a!=b][:16])
 for page,data in current.items():
  if base<=page<<12<base+0x400000:assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),(label,'image',hex(page<<12))
 return dict(label=label,base=hex(base),entry_sp=hex(entry_sp),parse_status=parsed.status,frees=len(expected),
  natural_return_and_SP_match=True,ordered_frees_sizes_and_owner_bytes_match=True,all_guest_heap_image_pages_match=True,native_snapshot_input=False)


def synthetic_owned(args,base):
 case=next(c for c in parse.fixtures() if c['label']=='empty')
 with v.arena(case):initial,parsed=prepare(args,base,case)
 output=oracle.GUEST+0xB100
 def put(p,a,value,width=8):_write_span(p,a,value.to_bytes(width,'little'))
 def storage(p,allocations,address,size):
  if size:_write_span(p,address,bytes(size))
  allocations.append(v.alternative.ReaderAstEffect('allocate',address,size,output,bytes(128)))
 def header(p,offset,begin,used,size):
  for n,value in enumerate((begin,begin+used,begin+size)):put(p,output+offset+n*8,value)
 for offset in (8,0x20,0x38,0x50,0x68):
  p={k:bytearray(value) for k,value in initial.items()};allocations=[];address=0x79001000
  storage(p,allocations,address,0);header(p,offset,address,0,0)
  yield 'nonnull_zero_capacity_'+str(offset),p,replace(parsed,effects=tuple(allocations))
 p={k:bytearray(value) for k,value in initial.items()};allocations=[]
 for i,(offset,stride) in enumerate(((8,64),(0x20,64),(0x38,32),(0x50,4),(0x68,1))):
  address=0x79001000+i*0x100;storage(p,allocations,address,stride*2);header(p,offset,address,0,stride*2)
 yield 'reserved_empty_vectors',p,replace(parsed,effects=tuple(allocations))
 for length in (0,22):
  p={k:bytearray(value) for k,value in initial.items()};allocations=[]
  for offset,address,size in ((8,0x79001000,64),(0x20,0x79001100,64),(0x38,0x79001200,32),
    (0x50,0x79001A00,4),(0x68,0x79001B00,2)):
   storage(p,allocations,address,size);header(p,offset,address,size,size)
  storage(p,allocations,0x79001300,24)
  for i,value in enumerate((0x79001300,0x7900130C,0x79001318)):put(p,0x79001028+i*8,value)
  for i,address in enumerate((0x79001010,0x79001100,0x79001118,0x79001200)):
   pointer=0x79001400+i*0x100;storage(p,allocations,pointer,32)
   put(p,address,33);put(p,address+8,length);put(p,address+16,pointer)
   _write_span(p,pointer,b's'*length+b'\0')
  put(p,output,2,4)
  yield 'owned_short_long_representation_'+str(length),p,replace(parsed,effects=tuple(allocations))


def negatives(args):
 base=v.BASES[0];_,initial,_=list(synthetic_owned(args,base))[-1]
 rows=[];output=oracle.GUEST+0xB100
 def put(p,a,value,width=8):_write_span(p,a,value.to_bytes(width,'little'))
 def reject(label,changes=None,mutation=None,fault=None):
  p={k:bytearray(value) for k,value in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(value) for k,value in p.items()};saved=v.alternative._write_span;hits=[]
  def write(current,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected cleanup write failure')
   return saved(current,address,data)
  try:
   if fault:v.alternative._write_span=write
   try:v.alternative.cleanup_parser_conversion(p,image_base=base,output_address=output,**(changes or {}))
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted cleanup guard '+label)
  finally:v.alternative._write_span=saved
  assert before=={k:bytes(value) for k,value in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 reject('record_budget',dict(max_nodes=2))
 reject('byte_budget',dict(max_vector_bytes=63))
 reject('reserved_output',dict(reserved_regions=((output,output+128),)))
 reject('reserved_owned_payload',dict(reserved_regions=((0x79001400,0x79001420),)))
 reject('reversed_vector',mutation=lambda p:put(p,output+16,0x79000FF8))
 reject('used_beyond_capacity',mutation=lambda p:put(p,output+16,0x79001080))
 reject('misaligned_vector',mutation=lambda p:put(p,output+8,0x79001001))
 reject('record_stride',mutation=lambda p:put(p,output+16,0x79001008))
 reject('null_begin_nonnull_capacity',mutation=lambda p:put(p,output+8,0))
 reject('vector_alias_owner',mutation=lambda p:put(p,output+8,output))
 reject('shared_owned_string',mutation=lambda p:put(p,0x79001110,0x79001400))
 reject('unmapped_owned_string',mutation=lambda p:put(p,0x79001020,0x76000000))
 reject('string_alias_record',mutation=lambda p:put(p,0x79001020,0x79001100))
 reject('string_in_image',mutation=lambda p:put(p,0x79001020,base+0x1000))
 reject('long_length_capacity',mutation=lambda p:put(p,0x79001018,32))
 reject('oversized_long_capacity',mutation=lambda p:put(p,0x79001010,0x1000001))
 reject('inline_length',mutation=lambda p:put(p,0x79001010,46,1))
 reject('decoded_stride',mutation=lambda p:put(p,0x79001030,0x79001310))
 reject('decoded_alias_string',mutation=lambda p:put(p,0x79001028,0x79001400))
 reject('early_data_write_failure',fault=lambda a,d:a==output+0x70)
 reject('late_function_write_failure',fault=lambda a,d:a==output+0x10)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.heap.LIBC_HASH
 rows=[];guards=negatives(args);cases=parse.fixtures()
 for base in v.BASES:
  for case in cases:
   with v.arena(case):
    p,result=prepare(args,base,case);rows.append(compare(args,base,p,result,case['label']))
  for label,p,result in synthetic_owned(args,base):rows.append(compare(args,base,p,result,label))
  print('Converted cleanup',hex(base),'synthetic passed',flush=True)
  case=v.actual_specs(args.library)[-1]
  with v.arena(case):
   p,result=prepare(args,base,case);assert result.function_count==139 and result.decoded_word_count==54533
   row=compare(args,base,p,result,'complete_actual_ELF');row['actual_ELF_complete_module']=True;rows.append(row)
  print('Converted cleanup',hex(base),'complete actual ELF passed',flush=True)
  case=next(c for c in cases if c['label']=='reassign_1_23_47_2_100_0')
  with v.arena(case):
   p,result=prepare(args,base,case)
   for delta in (-0xC80,0x100):rows.append(compare(args,base,p,result,case['label']+'_SP_'+str(delta),entry_sp=0x781FF000+delta))
  with v.previous.previous.previous.definitions.guest_layout(0x7000000000):
   for label in ('defined_export_47','import_3_47','data'):
    case=next(c for c in cases if c['label']==label)
    with v.arena(case):
     p,result=prepare(args,base,case);rows.append(compare(args,base,p,result,label+'_high_guest'))
 evidence=dict(schema='vm9-alternative-converted-cleanup-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=v.heap.LIBC_HASH,
  native_Python_converted_cleanup_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=16,
  complete_actual_ELF_module_controls=2,relocated_entry_stack_controls=4,relocated_full_guest_controls=6,
  native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Converted cleanup',len(rows),'native/Python',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
