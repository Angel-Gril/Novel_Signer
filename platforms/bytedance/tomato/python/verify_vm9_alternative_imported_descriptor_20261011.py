"""Fresh imported descriptors versus the unmodified ARM64 entry.

Synthetic borrowed-name maps and fresh Python reader/parse records are inputs.
Actual external callbacks come from original constructor instruction references.
Native snapshots are assertions only; complete factory boot is not claimed.
"""
from pathlib import Path
import argparse,hashlib,json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from unicorn import arm64_const as arm
import verify_vm9_alternative_defined_descriptor_20261011 as defined
from vm9_allocator import _read_span,_write_span,RefillUnsupported
oracle=defined.oracle;alternative=defined.alternative
HEAP=defined.HEAP;HEAP_SIZE=defined.HEAP_SIZE
FUNCTION=defined.FUNCTION;NAMES=defined.NAMES;OUTPUT=defined.OUTPUT
BINDINGS=oracle.GUEST+0xB700;BUCKETS=oracle.GUEST+0xD000;NODES=oracle.GUEST+0xD200
KEYS=oracle.GUEST+0x11000;SP=0x781FF000


def put(p,a,n,w=8):_write_span(p,a,n.to_bytes(w,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def binding_map(p,base,rows,count=19):
 _write_span(p,BINDINGS,bytes(32)+(0x3F800000).to_bytes(4,'little')+bytes(4))
 if not count:assert not rows;return
 _write_span(p,BUCKETS,bytes(count*8));put(p,BINDINGS,BUCKETS);put(p,BINDINGS+8,count)
 for index,(key,function) in enumerate(rows):
  pointer=KEYS+index*64;_write_span(p,pointer,key+b'\0');node=NODES+index*40
  hashed=alternative.hash_descriptor_name(key);bucket=hashed%count
  _write_span(p,node,b''.join(x.to_bytes(8,'little') for x in (0,hashed,pointer,len(key),function)))
  previous=u(p,BUCKETS+bucket*8)
  if previous:put(p,node,u(p,previous));put(p,previous,node)
  else:
   following=u(p,BINDINGS+16);put(p,node,following);put(p,BINDINGS+16,node);put(p,BUCKETS+bucket*8,BINDINGS+16)
   if following:put(p,BUCKETS+(u(p,following+8)%count)*8,node)
  put(p,BINDINGS+24,index+1)


def builtin_keys(args,base):
 # Decode source references directly from ELF; do not initialize a catalog or
 # read a native/model heap as a fixture.
 pages=oracle.image_pages(args.library,base);out=[]
 for method,length,decoder,literal in alternative._BUILTIN_FUNCTION_ENTRIES:
  if decoder:
   source,_,period,_=decoder;data=_read_span(pages,base+source,period+length+1)
   key=bytes(data[i%period]^data[period+i] for i in range(length))
  else:
   key=bytes(((u(pages,base+off,4)>>(5+byte*8))&255) if kind==0 else u(pages,base+off,1) for kind,off,byte in literal)
  out.append((key,base+method))
 return out


def prepare(args,base,*,name=b'stub',bound=True,padding=0xA5,long_rep=False,registry_ready=False,catalog_ready=False,bucket_count=19,extras=(),function=None,sp=SP,tid=137):
 p=defined.prepare(args,base,[],name=name,long_rep=long_rep,padding=padding,stack_padding=padding)
 header=_read_span(p,FUNCTION+16,24);_write_span(p,FUNCTION,bytes(64));_write_span(p,FUNCTION+24,header)
 if registry_ready:
  _write_span(p,base+0x3E2780,bytes(32)+(0x3F800000).to_bytes(4,'little')+bytes(44));put(p,base+0x3E27D0,(tid<<32)|0x101)
 if catalog_ready:
  cursor=0x79400000
  for a in range(cursor,cursor+0x10000,4096):p[a>>12]=bytearray(bytes([padding])*4096)
  def allocate(size):
   nonlocal cursor
   address=cursor;cursor+=(size+15)&~15;return address
  alternative.initialize_builtin_function_catalog(p,image_base=base,entry_stack_address=sp,thread_id=tid,allocate=allocate)
  for a in range(0x78000000,0x78200000,4096):p[a>>12]=bytearray(bytes([padding])*4096)
 rows=list(extras)
 if bound:rows.append((name,base+0x29E908 if function is None else function))
 binding_map(p,base,rows,bucket_count)
 return p


def driver():
 words=[0xA9BC7BFD,0xA90153F3,0xA9025BF5,0xA90363F7,
  0xAA0003F3,0xAA0103F4,0xAA0203F5,0xAA0303F6,0xAA0403F7,0xAA0503F8,
  0xAA1303E0,0xAA1403E1,0xAA1503E2,0xAA1603E8,0xD63F0300,
  0x91010273,0x910022D6,0xF10006F7,0x54000001|(((-8)&0x7FFFF)<<5),
  0xA94363F7,0xA94153F3,0xA9425BF5,0xA8C47BFD,0xD65F03C0]
 raw=b''.join(x.to_bytes(4,'little') for x in words);ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,0))
 assert ins[18].op_str=='#0x28' and ins[14].op_str=='x24'
 return raw


def native(args,base,p,*,function=FUNCTION,bindings=BINDINGS,names=NAMES,output=OUTPUT,count=1,sp=0x781FF000,tid=137,batch=False):
 saved=oracle.Uc,oracle.GUEST_SIZE;cpus=[];cursor=HEAP;events=[];finalizers=[];sizes={}
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw)
  for start,size in ((0x78000000,0x200000),(0x79000000,0x700000),(HEAP,HEAP_SIZE)):cpu.mem_map(start,size)
  cpus.append(cpu);return cpu
 def snapshot(cpu):return bytes(cpu.mem_read(output,count*8))
 def allocate(cpu,size):
  nonlocal cursor
  address=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=HEAP+HEAP_SIZE
  sizes[address]=size;events.append(('allocate',address,size,snapshot(cpu)));return address
 def free(cpu):
  address=cpu.reg_read(arm.UC_ARM64_REG_X0);events.append(('free',address,sizes[address],snapshot(cpu)));return 0
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)));return 0
 def memcmp(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,defined.builder.catalog.heap.libc_memcmp(args.libc));return None
 entry=0x2DC3E4;argv=[function,bindings,names];extra={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X8:output}
 if batch:
  entry=oracle.GUEST+0xA000-base;_write_span(p,base+entry,driver());argv=[function,bindings,names,output,count,base+0x2DC3E4]
  extra[arm.UC_ARM64_REG_X5]=base+0x2DC3E4
 try:
  oracle.Uc=factory;oracle.GUEST_SIZE=0x160000
  oracle.native(args.library,base,entry,argv,p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers=extra,instruction_limit=40000000,code_hook_ranges=((base+0x347E00,base+0x348800),))
 except Exception as error:
  cpu=cpus[0]
  raise AssertionError(('native imported driver',hex(cpu.reg_read(arm.UC_ARM64_REG_PC)),
   hex(cpu.reg_read(arm.UC_ARM64_REG_LR)),hex(cpu.reg_read(arm.UC_ARM64_REG_SP)))) from error
 finally:oracle.Uc,oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,events,finalizers


def compare(args,base,p,*,label,function=FUNCTION,count=1,batch=False,sp=SP,tid=137):
 cpu,events,finalizers=native(args,base,p,function=function,count=count,batch=batch,sp=sp,tid=tid)
 cursor=HEAP;calls=[];results=[];effects=[];entry_sp=sp-(64 if batch else 0)
 def allocate(size):
  nonlocal cursor
  address=cursor;cursor+=(size+15)&~15;calls.append((address,size));return address
 for index in range(count):
  published=_read_span(p,OUTPUT,count*8)
  result=alternative.construct_parser_imported_descriptor(p,image_base=base,import_address=function+index*64,
   bindings_address=BINDINGS,names_address=NAMES,output_address=OUTPUT+index*8,entry_stack_address=entry_sp,
   thread_id=tid,allocate=allocate)
  assert result.address==int.from_bytes(cpu.mem_read(OUTPUT+index*8,8),'little'),(label,index)
  for effect in result.effects:
   assert effect.owner_address==OUTPUT+index*8
   snapshot=published[:index*8]+effect.owner_bytes+published[(index+1)*8:]
   effects.append((effect.kind,effect.address,effect.size,snapshot))
  results.append(result)
 assert calls==[(a,n) for k,a,n,_ in events if k=='allocate'],label
 assert effects==events,(label,'ordered effects/publication')
 assert [f for r in results for f in r.finalizers]==finalizers,label
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 temporary=entry_sp-0x600;width=47 if results[-1].address else 16
 assert _read_span(p,temporary,width)==bytes(cpu.mem_read(temporary,width)),(label,'name temporary')
 return dict(base=hex(base),label=label,descriptors=count,constructed=sum(bool(r.address) for r in results),
  binding_matches=sum(r.source=='binding' for r in results),builtin_matches=sum(r.source=='builtin' for r in results),
  missing_matches=sum(r.source=='missing' for r in results),allocations=len(calls),frees=sum(e[0]=='free' for e in effects),
  finalizers=len(finalizers),natural_return_SP_and_output_match=True,all_guest_heap_image_pages_match=True,
  ordered_effects_owner_publication_and_finalizers_match=True,consumed_name_temporary_match=True,
  native_snapshot_input=False)


def actual_input(args,base):
 p,_=defined.actual_input(args,base);module=oracle.GUEST+0xB100
 begin,end=u(p,module+0x20),u(p,module+0x28)
 records=[_read_span(p,a,64) for a in range(begin,end,64) if u(p,a+48,4)==0]
 assert len(records)==18
 function=oracle.GUEST+0xE000;_write_span(p,function,b''.join(records))
 builtin=dict(builtin_keys(args,base));bindings=constructor_bindings(args,base);external=dict(bindings);fallbacks=0
 for i in range(18):
  a=function+i*64;h=_read_span(p,a+24,24)
  n=int.from_bytes(h[8:16],'little') if h[0]&1 else h[0]>>1
  pointer=int.from_bytes(h[16:24],'little') if h[0]&1 else a+25;key=_read_span(p,pointer,n)
  if key in builtin:fallbacks+=1
  else:assert key in external
 assert len(bindings)==16 and fallbacks==2
 binding_map(p,base,bindings)
 _write_span(p,OUTPUT,bytes(18*8))
 return p,function


def constructor_bindings(args,base):
 # Sixteen consecutive seven-instruction records in the original constructor.
 # The ELF name address, callback address and zero registration flag are
 # derived from ADRP/ADD/STR instructions, without a native constructor run.
 pages=oracle.image_pages(args.library,base);dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM);dis.detail=True;rows=[]
 for index in range(16):
  address=0x29ECB8+index*28
  ins=list(dis.disasm(_read_span(pages,base+address,28),address))
  assert [i.mnemonic for i in ins]==['adrp','add','str','adrp','add','str','strb']
  assert ins[2].operands[1].mem.disp==0x2A0+index*24 and ins[5].operands[1].mem.disp==0x2A8+index*24
  assert ins[6].op_str.startswith('wzr,') and ins[6].operands[1].mem.disp==0x2B0+index*24
  pointer=base+ins[0].operands[1].imm+ins[1].operands[2].imm
  function=base+ins[3].operands[1].imm+ins[4].operands[2].imm
  raw=_read_span(pages,pointer,33);assert 0 in raw
  rows.append((raw[:raw.index(0)],function))
 assert len(dict(rows))==16
 return rows


def negatives(args):
 base=0x122C0000;initial=prepare(args,base);rows=[]
 def reject(label,changes=None,mutation=None,fault=None,builtin=False):
  p=prepare(args,base,bound=False) if builtin else {k:bytearray(v) for k,v in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(v) for k,v in p.items()};cursor=HEAP;hits=[]
  def allocate(size):
   nonlocal cursor
   a=cursor;cursor+=(size+15)&~15;return a
  kw=dict(image_base=base,import_address=FUNCTION,bindings_address=BINDINGS,names_address=NAMES,
   output_address=OUTPUT,entry_stack_address=SP,thread_id=137,allocate=allocate);kw.update(changes or {})
  saved=alternative._write_span
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected imported descriptor write failure')
   return saved(p,a,d)
  try:
   if fault:alternative._write_span=write
   try:alternative.construct_parser_imported_descriptor(p,**kw)
   except (ValueError,RefillUnsupported):pass
   else:raise AssertionError('accepted guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(v) for k,v in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),('thread_limit',dict(thread_id=1<<31)),
  ('negative_bindings_limit',dict(max_bindings=-1)),('boolean_bindings_limit',dict(max_bindings=True)),
  ('binding_budget',dict(max_bindings=0)),('byte_budget',dict(max_vector_bytes=63)),('no_allocator',dict(allocate=None)),
  ('unmapped_allocator',dict(allocate=lambda n:0x76000000)),('input_alias_allocator',dict(allocate=lambda n:FUNCTION)),
  ('borrowed_alias_allocator',dict(allocate=lambda n:KEYS)),('temporary_alias_allocator',dict(allocate=lambda n:SP-0x600)),
  ('reserved_heap',dict(reserved_regions=((HEAP,HEAP+HEAP_SIZE),))),('output_alias',dict(output_address=FUNCTION))):reject(label,changes)
 for label,address,value,width in (
  ('filter_nonempty',NAMES+24,1,8),('filter_load',NAMES+32,0,4),('registry_nonempty',base+0x3E2798,1,8),
  ('registry_busy',base+0x3E27D0,2,8),('mutex_busy',base+0x3E27A8,1,4),('inline_length',FUNCTION+24,46,1),
  ('binding_length',NODES+24,33,8),('binding_hash',NODES+8,u(initial,NODES+8)^1,8),
  ('binding_cycle',NODES,NODES,8),('binding_size',BINDINGS+24,2,8),('binding_load',BINDINGS+32,0,4),
  ('binding_predecessor',BUCKETS+(u(initial,NODES+8)%19)*8,0,8),('zero_bucket_count',BINDINGS+8,0,8)):
  reject(label,mutation=lambda p,a=address,v=value,w=width:put(p,a,v,w))
 for label,address in (('registry_write',base+0x3E2780),('guard_release',base+0x3E27D0),
  ('name_copy',SP-0x5F8),('descriptor_write',HEAP),('output_publication',OUTPUT)):
  reject(label,fault=lambda a,d,target=address:a==target)
 reject('nested_catalog_failure',builtin=True,fault=lambda a,d:a==base+0x3E2728)
 reject('nested_allocation_alias',builtin=True,changes=dict(allocate=lambda n:HEAP))
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==defined.builder.catalog.heap.LIBC_HASH
 rows=[];guards=negatives(args)
 for base in (0x122C0000,0x775C205000):
  keys=builtin_keys(args,base);short=next(k for k,_ in keys if len(k)==6);long=next(k for k,_ in keys if len(k)==29)
  cases=[('bound_'+str(n),dict(name=bytes((65+i%26 for i in range(n))))) for n in (0,1,4,8,9,16,17,22,23,29,32)]
  cases += [('heap_short_'+str(n),dict(name=b'h'*n,long_rep=True)) for n in (0,4,22)]
  cases += [('padding_'+str(pad),dict(padding=pad)) for pad in (0,0x39,0xFF)]
  cases += [('registry_ready',dict(registry_ready=True)),('zero_callback',dict(function=0)),
   ('builtin_override',dict(name=short)),('missing',dict(bound=False)),('empty_bindings',dict(bound=False,bucket_count=0))]
  for count in (1,8,17):
   cases.append(('collision_map_'+str(count),dict(bucket_count=count,extras=tuple((b'key_'+str(i).encode(),base+0x29E908) for i in range(12)))))
  for key in (short,long):
   for registry_ready,catalog_ready in ((False,False),(True,False),(False,True),(True,True)):
    cases.append(('builtin_'+str(len(key))+'_'+str(registry_ready)+'_'+str(catalog_ready),dict(name=key,bound=False,registry_ready=registry_ready,catalog_ready=catalog_ready)))
  for delta,tid in ((-0xC80,1),(0x100,0x7FFFFFFF)):
   cases.append(('SP_'+str(delta),dict(name=long,bound=False,sp=SP+delta,tid=tid)))
  for label,options in cases:
   p=prepare(args,base,**options);rows.append(compare(args,base,p,label=label,sp=options.get('sp',SP),tid=options.get('tid',137)))
  print('Imported descriptor',hex(base),len(cases),'synthetic controls passed',flush=True)
  p,function=actual_input(args,base)
  row=compare(args,base,p,label='fresh_actual_imports_ELF_constructor_callbacks',function=function,count=18,batch=True)
  assert row['binding_matches']==16 and row['builtin_matches']==2 and row['constructed']==18
  row['actual_ELF_import_records']=18;row['constructor_external_bindings_used']=True;rows.append(row)
  print('Imported descriptor',hex(base),'18 fresh actual imports with ELF constructor callbacks passed',flush=True)
 evidence=dict(schema='vm9-alternative-imported-descriptor-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=defined.builder.catalog.heap.LIBC_HASH,
  native_Python_imported_descriptor_controls=sum(r['descriptors'] for r in rows),native_driver_batches=len(rows),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=16,actual_ELF_import_records=36,
  actual_external_bindings_recovered=True,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  whole_native_stack_TLS_OS_compared=False,nonempty_registry_or_filter_implemented=False,
  full_root_construction_implemented=False,independent_Python_factory_implemented=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Imported descriptors',evidence['native_Python_imported_descriptor_controls'],'batches',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
