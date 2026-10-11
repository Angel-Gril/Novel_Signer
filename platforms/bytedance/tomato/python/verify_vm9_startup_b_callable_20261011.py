"""Fresh B callable ownership controls and A/queue callable regressions."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_startup as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
SOURCE=oracle.GUEST+0x1000;DEST=oracle.GUEST+0x2000;HEAP=oracle.GUEST+0x4000


def put(p,a,value):_write_span(p,a,value.to_bytes(8,'little'))


def prepare(args,base,table,label,padding=0xA5):
 p=oracle.fresh_pages();p.update(oracle.image_pages(args.library,base))
 for address in (SOURCE,DEST,HEAP,HEAP+64):_write_span(p,address,bytes([padding])*48)
 pointer=0 if 'empty' in label else HEAP if 'heap' in label else SOURCE
 put(p,SOURCE+32,pointer);put(p,DEST+32,0)
 if pointer:put(p,pointer,base+table);put(p,pointer+8,0xFEDCBA9876543210)
 if label=='assign_replace':put(p,DEST+32,HEAP+64);put(p,HEAP+64,base+0x35D630)
 destination=SOURCE if 'self' in label else DEST
 return p,destination


def model(p,base,label,destination):
 frees=[]
 def free(p,a):frees.append(a)
 if label.startswith('move'):startup.move_callable(p,destination_address=destination,source_address=SOURCE,image_base=base)
 elif label.startswith('assign'):startup.assign_callable(p,destination_address=destination,source_address=SOURCE,image_base=base,free=free)
 else:startup.destroy_callable(p,object_address=SOURCE,image_base=base,free=free,reset=label.startswith('reset'))
 return frees


def compare(args,base,table,label,padding=0xA5):
 p,destination=prepare(args,base,table,label,padding);expected=[];cpus=[];old=oracle.Uc
 def make(*a,**kw):cpu=old(*a,**kw);cpus.append(cpu);return cpu
 def free(cpu):expected.append(cpu.reg_read(arm.UC_ARM64_REG_X0));return 0
 entry=0x3259C4 if label.startswith('move') else 0x291848 if label.startswith('assign') else 0x2918B0 if label.startswith('reset') else 0x167310
 arguments=[destination,SOURCE] if label.startswith(('move','assign')) else [SOURCE]
 try:
  oracle.Uc=make;_,memory,_,_=oracle.native(args.library,base,entry,arguments,p,host_imports={0x347FA0:free})
 finally:oracle.Uc=old
 assert cpus[0].reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
 frees=model(p,base,label,destination)
 assert frees==expected and _read_span(p,oracle.GUEST,0xA000)==memory
 assert all(bytes(data)==bytes(cpus[0].mem_read(page<<12,4096)) for page,data in p.items() if base<=page<<12<base+0x400000)
 return dict(base=hex(base),vtable_offset=hex(table),label=label,padding=padding,
  frees=len(frees),natural_return_and_SP_match=True,guest_payloads_and_image_match=True,
  ordered_frees_match=True,native_snapshot_input=False)


def negatives(args):
 base=0x122C0000;rows=[]
 for label,operation,table_offset,target in (
  ('B_clone_method','move_inline',0x35FC28+0x18,0),
  ('B_clone_GOT','move_inline',0x387CB0,0),
  ('B_inline_destructor','destroy_inline',0x35FC28+0x20,0),
  ('B_heap_destructor','destroy_heap',0x35FC28+0x28,0),
  ('B_reset_inline_destructor','reset_inline',0x35FC28+0x20,0),
  ('B_reset_heap_destructor','reset_heap',0x35FC28+0x28,0),
  ('B_assign_clone_method','assign_inline',0x35FC28+0x18,0),
  ('B_assign_GOT','assign_replace',0x387CB0,0)):
  p,dest=prepare(args,base,0x35FC28,operation);put(p,base+table_offset,target)
  before={k:bytes(v) for k,v in p.items()}
  try:model(p,base,operation,dest)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,operation,address in (('move_header_write','move_inline',DEST),('move_pointer_write','move_inline',DEST+32),
  ('reset_write','reset_inline',SOURCE+32),('assign_write','assign_inline',DEST)):
  p,dest=prepare(args,base,0x35FC28,operation);before={k:bytes(v) for k,v in p.items()};saved=startup._write_span;hits=[]
  def write(p,a,data):
   if a==address:hits.append(a);raise RefillUnsupported('injected B callable write failure')
   return saved(p,a,data)
  try:
   startup._write_span=write
   try:model(p,base,operation,dest)
   except RefillUnsupported:pass
   else:raise AssertionError(label)
  finally:startup._write_span=saved
  assert hits and before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 guards=negatives(args);rows=[]
 labels=('move_inline','move_heap','move_empty','destroy_inline','destroy_heap','destroy_empty',
  'reset_inline','reset_heap','assign_inline','assign_heap','assign_self_inline','assign_self_heap','assign_replace')
 for base in (0x122C0000,0x775C205000):
  for table in (0x35D630,0x35FC28,0x372600):
   for label in labels:rows.append(compare(args,base,table,label))
  for padding in (0,0x39,0xFF):rows.append(compare(args,base,0x35FC28,'move_inline',padding))
  print('Shared callable',hex(base),'passed',flush=True)
 evidence=dict(schema='vm9-startup-b-callable-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,native_Python_callable_controls=len(rows),rollback_negative_controls=len(guards),
  B_callable_controls=sum(r['vtable_offset']=='0x35fc28' for r in rows),existing_A_queue_regression_controls=sum(r['vtable_offset']!='0x35fc28' for r in rows),
  pre_change_behavior_RED_controls=12,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  entire_B_startup_composed=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Callable controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
