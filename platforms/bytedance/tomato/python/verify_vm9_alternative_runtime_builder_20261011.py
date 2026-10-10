"""Fresh actual virtual instruction builders and complete actual ELF word controls.

A small AArch64 driver calls each original builder, without substituting its
body. Model inputs come from Python constructors/reader/parse and fresh ELF.
Private names, decoded payloads and native snapshots are never published.
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
  0x39401288,0xF8687A60,0xAA1403E1,0xF9400009,0xF9400129,0xAA1503E8,0xD63F0120,
  0x91003294,0x910102B5,0xF10006D6,0x54000001|(((-10)&0x7FFFF)<<5),
  0xA94153F3,0xA9425BF5,0xA8C47BFD,0xD65F03C0]
 raw=b''.join(w.to_bytes(4,'little') for w in words)
 ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,0))
 assert len(ins)==len(words) and ins[7].op_str=='w8, [x20, #4]' and ins[8].op_str=='x0, [x19, x8, lsl #3]'
 assert ins[17].mnemonic=='b.ne' and ins[17].op_str=='#0x1c'
 return raw

def native(args,base,records,*,padding=0xA5,sp=0x781FF000,slots=()):
 assert records and all(len(row)==12 and row[4]<64 for row in records)
 p=catalog.prepare(args,base,warm=True,pad=padding)
 root,child,source,destination=0x79200000,0x79300000,0x79600000,0x79700000
 for index,offset in slots:_write_span(p,root+index*8,(root+offset).to_bytes(8,'little'))
 source_size=(len(records)*12+4095)&~4095;destination_size=(len(records)*64+4095)&~4095
 assert source+source_size<=destination and destination_size<=0x400000
 for start,size in ((source,source_size),(destination,destination_size)):
  for address in range(start,start+size,4096):p[address>>12]=bytearray(bytes([padding])*4096)
 _write_span(p,source,b''.join(records));entry=oracle.GUEST+0xA000;_write_span(p,entry,driver())
 saved=oracle.Uc;cpus=[]
 def factory(*a,**kw):
  cpu=saved(*a,**kw)
  for start,size in ((root,0x9000),(child,0x4000),(0x78000000,0x200000),(source,source_size),(destination,destination_size)):cpu.mem_map(start,size)
  cpus.append(cpu);return cpu
 try:
  oracle.Uc=factory
  oracle.native(args.library,base,entry-base,[root,source,destination,len(records)],p,
   extra_registers={arm.UC_ARM64_REG_SP:sp},instruction_limit=20000000,
   code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,p,source,destination


def decoded(word):
 return word.to_bytes(4,'little')+bytes([word>>26,*((word>>shift)&31 for shift in (21,16,11,6)),word&63])+b'\xa5\xa5'


def graph_cases(args,base):
 p=catalog.prepare(args,base,warm=True);root=0x79200000
 tables={off:size for off,size,_ in alternative._INSTRUCTION_BUILDER_TABLES}
 complex_={0x2F6940,0x2F6A00,0x2F6B70,0x2F6CCC,0x2F6D50,0x2F6F28,0x2F705C,0x31B1A0}
 getters={0x2F6A6C:9,0x2F6BDC:5,0x2F6BE4:8,0x313884:6}
 def u(a):return int.from_bytes(_read_span(p,a,8),'little')
 def walk(node,fields,depth=0):
  assert depth<8
  table=u(node);function=u(table)-base
  if function not in complex_ or function in (0x2F6CCC,0x2F6D50,0x31B1A0):yield function,fields;return
  if function in (0x2F6940,0x2F6F28):
   yield from walk(node+(32 if function==0x2F6940 else 16),fields,depth+1);return
  if function==0x2F705C:
   yield from walk(node+0x220,fields,depth+1);yield from walk(node+16,fields,depth+1);return
  assert function in (0x2F6A00,0x2F6B70)
  field=getters[u(table+8)-base];size=tables[node-root+16]
  for key in range(size//8):
   child=u(node+16+key*8)
   if child and (field not in fields or fields[field]==key):yield from walk(child,{**fields,field:key},depth+1)
 def selected(node,data,depth=0):
  assert depth<8
  if not node:return None
  table=u(node);function=u(table)-base
  if function not in complex_ or function in (0x2F6CCC,0x2F6D50,0x31B1A0):return function
  if function in (0x2F6940,0x2F6F28):return selected(node+(32 if function==0x2F6940 else 16),data,depth+1)
  if function==0x2F705C:return selected(node+0x220,data,depth+1) or selected(node+16,data,depth+1)
  field=getters[u(table+8)-base];return selected(u(node+16+data[field]*8),data,depth+1)
 records=[];traps=[]
 for opcode in range(64):
  for function,fields in walk(u(root+opcode*8),{4:opcode}):
   initial=bytearray(b'\x78\x56\x34\x12'+bytes(6)+b'\xa5\xa5')
   for field,value in fields.items():initial[field]=value
   candidates=[bytes(initial)]
   for field in (5,6,7,8,9):
    if field in fields:continue
    for value in range(32 if field!=9 else 64):
     raw=bytearray(initial);raw[field]=value;candidates.append(bytes(raw))
   for raw in candidates:
    if selected(u(root+opcode*8),raw)!=function:continue
    if function==0x2F6D50 or function==0x2F6CCC and raw[7]:traps.append(raw);continue
    records.append(raw);break
 records.append(decoded(0));assert len(records)==422 and traps
 # Independently enumerate original vtable methods; output values remain native assertions.
 leaves={}
 for offset,table,_ in alternative._INSTRUCTION_BUILDER_NODES:
  method=u(base+table)-base
  if method not in complex_:leaves.setdefault(method,offset)
 assert len(leaves)==187
 return records,sorted(leaves.items()),list(dict.fromkeys(traps))


def compare(args,base,records,label,**options):
 cpu,p,source,destination=native(args,base,records,**options)
 stack=_read_span(p,0x78000000,0x200000);statuses=Counter()
 for index in range(len(records)):
  result=alternative.build_parser_runtime_instruction(p,image_base=base,catalog_address=0x79200000,
   decoded_address=source+index*12,output_address=destination+index*64)
  assert not result.effects and result.status==bytes(cpu.mem_read(destination+index*64+48,1))[0]
  statuses[result.status]+=1
 assert _read_span(p,0x78000000,0x200000)==stack
 for page,data in p.items():
  if not 0x78000000<=page<<12<0x78200000:assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),(label,hex(page<<12))
 return dict(label=label,base=hex(base),instructions=len(records),constructed=statuses[1],not_constructed=statuses[0],
  padding=options.get('padding',0xA5),entry_sp=hex(options.get('sp',0x781FF000)),
  virtual_slots_overridden=bool(options.get('slots')),natural_return_and_SP_match=True,
  all_guest_heap_image_pages_match=True,all64_output_bytes_and_validity_match=True,model_stack_unchanged=True,native_snapshot_input=False)


def negatives(args,trap):
 base=0x122C0000;initial=catalog.prepare(args,base,warm=True);source=oracle.GUEST+0xB000;output=oracle.GUEST+0xB100
 _write_span(initial,source,decoded(0x00000001));_write_span(initial,output,b'\xa5'*64)
 rows=[]
 def put(p,a,n):_write_span(p,a,n.to_bytes(8,'little'))
 def reject(label,changes=None,mutation=None,fault=None):
  p={k:bytearray(value) for k,value in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(value) for k,value in p.items()};saved=alternative._write_span;hits=[]
  params=dict(image_base=base,catalog_address=0x79200000,decoded_address=source,output_address=output);params.update(changes or {})
  def write(current,a,data):
   if fault(a,data):hits.append(a);raise RefillUnsupported('injected runtime builder write failure')
   return saved(current,a,data)
  try:
   if fault:alternative._write_span=write
   try:alternative.build_parser_runtime_instruction(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted instruction guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(value) for k,value in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('zero_depth',dict(max_dispatch=0)),('boolean_depth',dict(max_dispatch=True)),('excess_depth',dict(max_dispatch=65)),
  ('exhausted_depth',dict(max_dispatch=1)),('unmapped_catalog',dict(catalog_address=0x76000000)),
  ('unmapped_input',dict(decoded_address=0x76000000)),('unmapped_output',dict(output_address=0x76000000)),
  ('output_alias_input',dict(output_address=source)),('output_alias_catalog',dict(output_address=0x79200000)),
  ('input_alias_catalog',dict(decoded_address=0x79200000)),('unaligned_output',dict(output_address=output+1)),
  ('reserved_output',dict(reserved_regions=((output,output+64),)))):reject(label,changes)
 reject('primary_opcode_bound',mutation=lambda p:_write_span(p,source+4,b'\x40'))
 reject('primary_null_node',mutation=lambda p:put(p,0x79200000,0))
 reject('primary_unknown_node',mutation=lambda p:put(p,0x79200000,0x79200008))
 reject('wrong_node_vtable',mutation=lambda p:put(p,0x79200208,base+0x368978))
 reject('unsupported_virtual_method',mutation=lambda p:put(p,base+0x368960,base+0x347F40))
 reject('unsupported_getter',mutation=lambda p:put(p,base+0x368990+8,base+0x347F40))
 reject('selector_bound',mutation=lambda p:_write_span(p,source+9,b'\xff'))
 reject('dispatch_cycle',mutation=lambda p:put(p,0x79200238+8,0x79200228))
 reject('diagnostic_trap',mutation=lambda p:_write_span(p,source,trap))
 reject('operand_write_failure',fault=lambda a,d:a==output)
 reject('tag_write_failure',fault=lambda a,d:a==output+40)
 reject('validity_write_failure',fault=lambda a,d:a==output+48)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==catalog.heap.LIBC_HASH
 graphs,leaves,traps=graph_cases(args,0x122C0000);guards=negatives(args,traps[0]);rows=[]
 missing=[decoded(w) for w in (0xF,0x1F,0x44000001,0x44000007,0x4400000F,0x44000017,0x4400001F,0x4400002F,
  0x4400003F,0x7C000000,0x7C000001,0x7C000007,0x7C00000F,0x7C000017,0x7C00001F,0x7C00002F,0x7C00003F,
  0xB0000000,0xB000000F,0xB0000017,0xB000003F,0xF8000007,0xF800000F,0xF800003F)]
 for base in (0x122C0000,0x775C205000):
  rows.append(compare(args,base,graphs,'all_graph_paths'))
  row=compare(args,base,missing,'missing_nested_entries');assert row['not_constructed']==24;rows.append(row)
  for group_start in range(0,len(leaves),64):
   group=leaves[group_start:group_start+64];records=[]
   for slot,(method,offset) in enumerate(group):
    for word,fields in ((0,b'\0'*5),(0xFFFFFFFF,b'\xff'*5),(0x1FFFF,b'\1\x80\x7f\xff\x1f'),
     (0x20000,b'\x1f\2\x10\x03\x3f'),(0x3FFFFFF,b'\x55\xaa\x33\xcc\x15'),(0xA55A5AA5,b'\xa5\x39\xff\0\x2a')):
     records.append(word.to_bytes(4,'little')+bytes([slot])+fields+b'\x39\x5a')
   rows.append(compare(args,base,records,'leaf_methods_'+str(group_start),slots=tuple((i,offset) for i,(_,offset) in enumerate(group))))
  for pad in (0,0x39,0xFF):rows.append(compare(args,base,graphs,'graph_padding_'+str(pad),padding=pad))
  for delta in (-0xC80,0x100):rows.append(compare(args,base,graphs,'graph_SP_'+str(delta),sp=0x781FF000+delta))
  print('Runtime instruction builders',hex(base),'synthetic passed',flush=True)
  v=converted.v;case=v.actual_specs(args.library)[-1]
  with v.arena(case):p,result=converted.prepare(args,base,case)
  assert result.function_count==139 and result.decoded_word_count==54533
  def u(a):return int.from_bytes(_read_span(p,a,8),'little')
  records=[];output=oracle.GUEST+0xB100
  for record in range(u(output+8),u(output+16),64):
   records.extend(_read_span(p,a,12) for a in range(u(record+40),u(record+48),12))
  assert len(records)==54533
  row=compare(args,base,records,'complete_actual_ELF');assert row['constructed']==54533
  row['actual_ELF_complete_module']=True;rows.append(row)
  print('Runtime instruction builders',hex(base),'54533 actual words passed',flush=True)
 evidence=dict(schema='vm9-alternative-runtime-builder-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=catalog.heap.LIBC_HASH,
  native_Python_runtime_instruction_controls=sum(r['instructions'] for r in rows),native_driver_batches=len(rows),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=12,actual_ELF_complete_module_batches=2,
  actual_ELF_instruction_controls=109066,synthetic_graph_paths_per_base=422,linear_leaf_methods_per_base=187,
  missing_nested_entry_controls=48,relocated_SP_batches=4,alternate_padding_batches=6,
  native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  runtime_vector_move_implemented=False,root_linking_second_pass_implemented=False,independent_Python_factory_implemented=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Runtime instruction builders',evidence['native_Python_runtime_instruction_controls'],'calls in',len(rows),'batches,',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
