"""B worker instruction execution from fresh ELF with explicit imported providers.

Imported bodies are not executed by these runtime controls. The separate
startup regressions execute their actual enqueue/destroy composition. Worker
once initializers and full JNI/bootstrap remain separate recovery boundaries.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_startup_20261011 as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import verify_vm9_alternative_runtime_20261011 as r
v=r.v
RECIPES={194:(188,62,95),273:(102,134,169),361:(169,169,188),402:(55,55,169,169),651:(102,134,134),726:(134,55,134,55)}


def synthetic(args,base,label):
 p,selected,functions=r.synthetic(args,base,'call');r.put(p,r.CONTEXT+0x6090,0)
 if label.startswith('imm_'):
  imm=int(label.split('_')[1]);r.record(p,r.CODE,62,r.word(0,7,imm));r.record(p,r.CODE+48,189);count=2
 elif label.startswith('branch_'):
  equal=label.endswith('equal');r.put(p,r.CONTEXT+0x6078,0x89ABCDEF01234567 if equal else 0x89ABCDEE01234567)
  r.put(p,r.CONTEXT+0x6080,0x89ABCDEF01234567)
  r.record(p,r.CODE,95,r.word(5,6,1));r.record(p,r.CODE+48,189,3)
  r.record(p,r.CODE+96,95,r.word(5,6,-2));count=3
 else:
  tag=int(label.split('_')[1]);seq=RECIPES[tag];count=len(seq)+2;r.record(p,r.CODE,tag)
  # Deliberately make a fused load read status, exposing whether its own
  # status increment occurs before or after the load.
  r.put(p,r.CONTEXT+0x6070,r.CONTEXT if label.endswith('_status') else r.DATA+0x100)
  r.put(p,r.ROOT+72,r.DATA+0x100)
  for i,operation in enumerate(seq):
   a=r.CODE+(i+1)*48
   packed=(1 if operation==188 else r.word(0,7,-17) if operation==62 else
    r.word(5,6,0) if operation==95 else r.word(5,0,8) if operation==169 else
    r.word(4,5 if operation==55 else 6,0 if label.endswith('_status') else 8*i))
   # Stores must stay in data; status-reading cases only target load inputs.
   if operation==55:
    r.put(p,r.CONTEXT+0x60A8,r.DATA+0x200);packed=r.word(11,5,8*i)
   r.record(p,a,0xFFFFFFFF,packed,r.ROOT if operation==188 else r.ROOT+72 if operation==102 else 0)
   r.put(p,r.CODE+(len(seq)-i-1)*8,a)
  r.record(p,r.CODE+(count-1)*48,189)
 r.descriptor(p,r.DESCRIPTOR,r.CODE,count)
 return p,selected,functions


def labels():return [f'imm_{i}' for i in (-32768,-17,0,17,32767)]+['branch_equal','branch_different']+['fused_'+str(i)+suffix for i in RECIPES for suffix in ('','_status')]


def changed_return_pc(args,base):
 p,selected,functions=synthetic(args,base,'fused_194')
 r.record(p,r.CODE+5*48,189);r.descriptor(p,r.DESCRIPTOR,r.CODE,6)
 saved=v.oracle.native
 def native(*a,**kw):
  previous=kw['host_imports'][0x29E908]
  def imported(cpu):
   result=previous(cpu)
   address=r.CONTEXT+0x6068
   value=int.from_bytes(cpu.mem_read(address,8),'little')
   cpu.mem_write(address,(value+1).to_bytes(8,'little'))
   return result
  kw['host_imports'][0x29E908]=imported
  return saved(*a,**kw)
 try:
  v.oracle.native=native;cpu,expected=r.native(args,base,p,selected,functions)
 finally:v.oracle.native=saved
 calls=[]
 def imported(p,function,ctx,sp):
  active=v.u(p,ctx+8)
  calls.append((function,ctx,sp,_read_span(p,ctx,0x62D0),_read_span(p,active,16)))
  r.put(p,ctx+0x6068,v.u(p,ctx+0x6068)+1)
 result=r.alternative.execute_runtime_descriptor(p,image_base=base,descriptor_address=selected,
  context_address=r.CONTEXT,entry_stack_address=v.SP,call_import=imported)
 assert calls==expected and result.imported_calls==tuple(row[:3] for row in calls)
 startup.pages_equal(p,cpu)
 return dict(base=hex(base),label='fused_194_changed_return_PC',dispatches=result.steps,imported_calls=len(calls),
  natural_return_SP_and_status_match=True,all_guest_heap_image_pages_match=True,
  imported_context_active_frame_and_SP_match=True,native_snapshot_input=False)


def negatives(args):
 rows=r.negatives(args);base=0x122C0000
 def reject(label,recipe,mutation=None,changes=None):
  p,selected,functions=synthetic(args,base,recipe)
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()}
  kw=dict(image_base=base,descriptor_address=selected,context_address=r.CONTEXT,
   entry_stack_address=v.SP,call_import=lambda *a:None);kw.update(changes or {})
  try:r.alternative.execute_runtime_descriptor(p,**kw)
  except RefillUnsupported:pass
  else:raise AssertionError('accepted branch guard '+label)
  assert before=={k:bytes(data) for k,data in p.items()},label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 reject('immediate_register80','imm_0',lambda p:r.put(p,r.CODE,r.word(0,80,0),4))
 reject('branch_first_register80','branch_equal',lambda p:r.put(p,r.CODE,r.word(80,6,0),4))
 reject('branch_second_register80','branch_equal',lambda p:r.put(p,r.CODE,r.word(5,80,0),4))
 reject('branch_forward_escape','branch_equal',lambda p:r.put(p,r.CODE,r.word(5,6,32767),4))
 reject('branch_negative_escape','branch_equal',lambda p:r.put(p,r.CODE,r.word(5,6,-2),4))
 reject('branch_infinite_loop','branch_equal',lambda p:r.put(p,r.CODE,r.word(5,6,-1),4),dict(max_steps=8))
 for tag in RECIPES:
  reject('fused_operand_alias_'+str(tag),'fused_'+str(tag),lambda p:r.put(p,r.CODE,r.CODE))
 reject('fused_branch_escape','fused_194',lambda p:r.put(p,r.CODE+3*48,r.word(5,5,32767),4))
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[];startup_rows=[]
 old_labels=['return','imported','call','nested','169_0']+[f'{tag}_{imm}' for tag in (55,66,102,134) for imm in (-16,0,15)]+['fused_'+str(tag) for tag in r.RECIPES]
 for base in (0x122C0000,0x775C205000):
  for label in labels():
   p,selected,functions=synthetic(args,base,label)
   row=r.compare(args,base,p,selected,functions,label,mutate=True);row['new_worker_instruction_control']=True;rows.append(row)
  row=changed_return_pc(args,base);row['new_worker_instruction_control']=True;rows.append(row)
  for label in old_labels:
   p,selected,functions=r.synthetic(args,base,label)
   row=r.compare(args,base,p,selected,functions,'existing_'+label,mutate=True);row['existing_runtime_regression']=True;rows.append(row)
  p,selected,functions=r.synthetic(args,base,'fused_397',padding=0x39)
  row=r.compare(args,base,p,selected,functions,'existing_relocated_SP_padded',sp=v.SP-0xC80,mutate=True)
  row['existing_runtime_regression']=True;rows.append(row)
  print('Worker runtime synthetic and old regression controls passed',hex(base),flush=True)
  p=r.constructor.prepare(args,base);built=r.constructor.model(p,base);root=built.address
  functions={v.u(p,v.u(p,v.u(p,root)+i*8)) for i in range(v.u(p,root+24))}
  initial={k:bytearray(data) for k,data in p.items()};r.context(initial)
  row=r.compare(args,base,initial,v.u(p,base+0x3E1EB8),functions,'existing_actual_initial_descriptor')
  row['existing_runtime_regression']=True;rows.append(row)
  for index in range(6):
   for branch in ('cold','hot'):
    selected=v.u(p,base+0x3E21F0+index*8);pages={k:bytearray(data) for k,data in p.items()}
    r.context(pages);r.put(pages,r.CONTEXT+0x6080,0 if branch=='cold' else (1<<64)-1)
    row=r.compare(args,base,pages,selected,functions,f'actual_worker_{index}_{branch}')
    row['actual_ELF_worker_descriptor']=True;row['imported_callback_bodies_executed']=False;rows.append(row)
  startup.setup(p,args)
  for sp,tid,label in ((v.SP,137,'startup_regression'),(v.SP-0xC80,1,'startup_relocated_regression')):
   startup_rows.append(startup.startup_compare(args,base,p,sp,tid,label))
  print('Worker actual descriptors and startup regressions passed',hex(base),flush=True)
 evidence=dict(schema='vm9-alternative-worker-runtime-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_runtime_controls=len(rows),new_worker_instruction_controls=40,existing_runtime_regression_controls=48,
  actual_ELF_worker_descriptor_controls=24,actual_B_startup_regression_controls=len(startup_rows),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=16,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,
  explicit_pure_imported_providers=True,worker_imported_callback_bodies_executed=False,
  full_B_worker_executed=False,full_JNI_bootstrap_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,startup_regressions=startup_rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Worker runtime',len(rows),'startup regressions',len(startup_rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
