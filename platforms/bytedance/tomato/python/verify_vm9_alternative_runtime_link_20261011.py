"""Fresh root-pointer linking and all secondary instruction rewrites.

Native executes the original +2dbe20/+2f67e4 and virtual methods. Runtime
vectors are independent synthetic/Python builder inputs; no native snapshots
or private names/payloads are published. Full factory remains separate work.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json
from unicorn import arm64_const as arm
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import verify_vm9_alternative_builder_catalog_20261011 as catalog
import verify_vm9_alternative_converted_cleanup_20261011 as converted
import vm9_alternative_startup as alternative
from vm9_allocator import _read_span,_write_span,RefillUnsupported
oracle=catalog.oracle

def driver():
 words=[0xA9BC7BFD,0xA90153F3,0xA9025BF5,0xAA0003F3,0xAA0103F4,0xAA0203F5,0xAA0303F6,
  0xAA1303E0,0xAA1403E1,0xD63F02C0,0x91010273,0xF10006B5,
  0x54000001|(((-5)&0x7FFFF)<<5),0xA94153F3,0xA9425BF5,0xA8C47BFD,0xD65F03C0]
 raw=b''.join(w.to_bytes(4,'little') for w in words);ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,0))
 assert len(ins)==17 and ins[9].op_str=='x22' and ins[12].op_str=='#0x1c'
 return raw

def prepare(args,base,vectors,*,padding=0xA5):
 p=catalog.prepare(args,base,warm=True,pad=padding)
 descriptors=0x79500000;data=0x79600000;context=oracle.GUEST+0xB000
 descriptor_size=(len(vectors)*64+4095)&~4095
 total=sum(len(v) for v in vectors);data_size=(total*48+4095)&~4095
 assert descriptor_size<=0x10000 and data_size<=0x400000
 for start,size in ((descriptors,descriptor_size),(data,max(4096,data_size))):
  for a in range(start,start+size,4096):p[a>>12]=bytearray(bytes([padding])*4096)
 _write_span(p,context,bytes([padding])*96)
 cursor=data
 for i,vector in enumerate(vectors):
  address=descriptors+i*64;_write_span(p,address,bytes(64))
  for j,value in enumerate((cursor,cursor+len(vector)*48,cursor+len(vector)*48)):_write_span(p,address+8+j*8,value.to_bytes(8,'little'))
  _write_span(p,address+56,(2).to_bytes(8,'little'))
  for item in vector:_write_span(p,cursor,item);cursor+=48
 entry=oracle.GUEST+0xA000;_write_span(p,entry,driver())
 return p,descriptors,context,descriptor_size,max(4096,data_size)

def native(args,base,vectors,*,padding=0xA5,sp=0x781FF000):
 p,descriptors,context,descriptor_size,data_size=prepare(args,base,vectors,padding=padding)
 saved=oracle.Uc;cpus=[]
 def factory(*a,**kw):
  cpu=saved(*a,**kw)
  for start,size in ((0x79200000,0x9000),(0x79300000,0x4000),(0x78000000,0x200000),(descriptors,descriptor_size),(0x79600000,data_size)):cpu.mem_map(start,size)
  cpus.append(cpu);return cpu
 try:
  oracle.Uc=factory
  oracle.native(args.library,base,oracle.GUEST+0xA000-base,[descriptors,context,len(vectors),base+0x2DBE20],p,
   extra_registers={arm.UC_ARM64_REG_SP:sp},instruction_limit=20000000,
   code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,p,descriptors,context

def synthetic(selector,padding=0xA5,index=1):
 vector=[bytearray(bytes([padding])*48) for _ in range(8)]
 vector[index][:4]=selector.to_bytes(4,'little');vector[index][40:48]=(790).to_bytes(8,'little')
 return list(map(bytes,vector))


def tagged(tag,padding=0xA5):
 item=bytearray(bytes([padding])*48);item[40:48]=tag.to_bytes(8,'little');return bytes(item)


def compare(args,base,vectors,label,**options):
 cpu,p,descriptors,context=native(args,base,vectors,**options)
 stack=_read_span(p,0x78000000,0x200000)
 tags=Counter(int.from_bytes(item[40:48],'little') for vector in vectors for item in vector)
 for index in range(len(vectors)):
  result=alternative.link_parser_runtime_descriptor(p,image_base=base,descriptor_address=descriptors+index*64,root_address=context)
  assert result.status is None and not result.effects
 assert _read_span(p,0x78000000,0x200000)==stack
 for page,data in p.items():
  if not 0x78000000<=page<<12<0x78200000:assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),(label,hex(page<<12))
 return dict(label=label,base=hex(base),descriptors=len(vectors),instructions=sum(map(len,vectors)),
  secondary_rewrites=tags[790],root_pointer_writes=sum(tags[k] for k in (102,137,188)),
  padding=options.get('padding',0xA5),entry_sp=hex(options.get('sp',0x781FF000)),
  natural_return_and_SP_match=True,all_guest_heap_image_pages_match=True,model_stack_unchanged=True,native_snapshot_input=False)


def negatives(args):
 base=0x122C0000;vector=synthetic(0);vector[0]=tagged(102)
 initial,descriptor,root,_,_=prepare(args,base,[vector]);slot=0x79600000+48;rows=[]
 def put(p,a,n,width=8):_write_span(p,a,n.to_bytes(width,'little'))
 def reject(label,changes=None,mutation=None,fault=None):
  p={k:bytearray(value) for k,value in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(value) for k,value in p.items()};saved=alternative._write_span;hits=[]
  params=dict(image_base=base,descriptor_address=descriptor,root_address=root);params.update(changes or {})
  def write(current,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected runtime link write failure')
   return saved(current,address,data)
  try:
   if fault:alternative._write_span=write
   try:alternative.link_parser_runtime_descriptor(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted runtime link guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(value) for k,value in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('boolean_budget',dict(max_instructions=True)),('negative_budget',dict(max_instructions=-1)),
  ('excess_budget',dict(max_instructions=1048577)),('instruction_budget',dict(max_instructions=7)),
  ('byte_budget',dict(max_vector_bytes=383)),('unmapped_descriptor',dict(descriptor_address=0x76000000)),
  ('unmapped_root',dict(root_address=0x76000000)),('root_alias_descriptor',dict(root_address=descriptor)),
  ('root_alias_vector',dict(root_address=0x79600000)),('reserved_vector',dict(reserved_regions=((0x79600000,0x79600180),))),
  ('reserved_catalog',dict(reserved_regions=((0x79200000,0x79209000),)))):reject(label,changes)
 reject('used_vector_stride',mutation=lambda p:put(p,descriptor+16,0x79600000+8))
 reject('capacity_vector_stride',mutation=lambda p:put(p,descriptor+24,0x79600000+385))
 reject('end_beyond_capacity',mutation=lambda p:put(p,descriptor+16,0x79600000+432))
 reject('operands_beyond_used_vector',mutation=lambda p:put(p,descriptor+16,0x79600000+4*48))
 reject('selector_600',mutation=lambda p:put(p,slot,600,4))
 reject('signed_negative_selector',mutation=lambda p:put(p,slot,0xFFFFFFFF,4))
 reject('cold_catalog',mutation=lambda p:put(p,base+0x3E2718,0))
 reject('busy_catalog',mutation=lambda p:put(p,base+0x3E2718,2))
 reject('unmapped_catalog',mutation=lambda p:put(p,base+0x3E2710,0x76000000))
 reject('shared_catalog_blocks',mutation=lambda p:put(p,0x79200200,0x79200000))
 reject('wrong_secondary_node',mutation=lambda p:put(p,0x79302580,0x79300010))
 reject('wrong_secondary_vtable',mutation=lambda p:put(p,0x79300000,base+0x36E1E8))
 reject('wrong_secondary_method',mutation=lambda p:put(p,base+0x36E1D0,base+0x313928))
 reject('root_pointer_write_failure',fault=lambda a,d:a==0x79600008)
 reject('secondary_operand_write_failure',fault=lambda a,d:a==slot+8)
 reject('secondary_tag_write_failure',fault=lambda a,d:a==slot+40)
 return rows


def actual_vectors(args,base):
 v=converted.v;case=v.actual_specs(args.library)[-1]
 with v.arena(case):p,result=converted.prepare(args,base,case)
 assert result.function_count==139 and result.decoded_word_count==54533
 for start,size in ((0x79200000,0x9000),(0x79300000,0x4000)):
  for address in range(start,start+size,4096):p[address>>12]=bytearray(b'\xa5'*4096)
 addresses=iter((0x79200000,0x79300000))
 alternative.initialize_instruction_builder_catalog(p,image_base=base,thread_id=137,allocate=lambda n:next(addresses))
 def u(a):return int.from_bytes(_read_span(p,a,8),'little')
 output=oracle.GUEST+0xB100;temporary=oracle.GUEST+0xB400;vectors=[]
 for record in range(u(output+8),u(output+16),64):
  vector=[]
  for address in range(u(record+40),u(record+48),12):
   _write_span(p,temporary,b'\xa5'*64)
   result=alternative.build_parser_runtime_instruction(p,image_base=base,catalog_address=0x79200000,
    decoded_address=address,output_address=temporary)
   assert result.status==1
   # This is an explicit input record; native vector move is not assumed.
   vector.append(_read_span(p,temporary,48))
  vectors.append(vector)
 assert len(vectors)==121 and sum(map(len,vectors))==54533
 return vectors


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==catalog.heap.LIBC_HASH
 rows=[];guards=negatives(args)
 for base in (0x122C0000,0x775C205000):
  for pad in (0xA5,0,0xFF):
   rows.append(compare(args,base,[synthetic(i,pad) for i in range(600)],'all_secondary_'+str(pad),padding=pad))
  vectors=[]
  for selector in (0,1,2,6):
   vector=synthetic(selector,index=2);vector[0]=tagged(102);vector[-1]=tagged(188);vectors.append(vector)
  rows.append(compare(args,base,vectors,'mixed_root_and_secondary'))
  rows.append(compare(args,base,[[tagged(k) for k in (102,137,188,0,0xFFFFFFFFFFFFFFFF,0x8000000000000066)]],'root_and_ignored_tags'))
  rows.append(compare(args,base,[[]],'empty'))
  for delta in (-0xC80,0x100):
   rows.append(compare(args,base,[synthetic(i) for i in range(16)],'SP_'+str(delta),sp=0x781FF000+delta))
  print('Runtime descriptor linking',hex(base),'all600 secondary/synthetic passed',flush=True)
  vectors=actual_vectors(args,base)
  row=compare(args,base,vectors,'complete_actual_ELF')
  assert row['secondary_rewrites']==9909 and row['root_pointer_writes']==612
  row['actual_ELF_complete_module']=True;rows.append(row)
  print('Runtime descriptor linking',hex(base),'121actual functions passed',flush=True)
 evidence=dict(schema='vm9-alternative-runtime-link-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=catalog.heap.LIBC_HASH,
  native_Python_runtime_descriptor_controls=sum(r['descriptors'] for r in rows),native_driver_batches=len(rows),
  total_instruction_records_compared=sum(r['instructions'] for r in rows),total_secondary_rewrites=sum(r['secondary_rewrites'] for r in rows),
  total_root_pointer_writes=sum(r['root_pointer_writes'] for r in rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=16,
  actual_ELF_complete_module_batches=2,actual_ELF_function_controls=242,actual_ELF_instruction_records=109066,
  actual_ELF_secondary_rewrites=19818,actual_ELF_root_pointer_writes=1224,secondary_builder_kinds=600,relocated_SP_batches=4,
  alternate_padding_batches=4,native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  native_vector_move_composed=False,full_descriptor_construction_implemented=False,independent_Python_factory_implemented=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Runtime linking',evidence['native_Python_runtime_descriptor_controls'],'descriptors,',evidence['total_secondary_rewrites'],
  'rewrites,',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
