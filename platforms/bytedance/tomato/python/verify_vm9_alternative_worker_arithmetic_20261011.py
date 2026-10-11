"""Full B worker arithmetic and CAS/memset builtins against original ARM64.

Synthetic edge controls and fresh actual nested descriptors use independent
Python inputs. Native pages are never model inputs. Full once/worker caller
composition and complete JNI/bootstrap remain separate recovery boundaries.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_alternative_worker_runtime_20261011 as previous
import verify_vm9_alternative_startup_20261011 as startup
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import verify_vm9_alternative_runtime_20261011 as r
v=r.v
NEW_PRIMARY=(0,2,48,49,50,74,77,84,89,103,105,120,138,144,146,147,153,165,187)
FUSED={193: (50, 66), 194: (188, 62, 95), 236: (2, 89, 120, 169), 250: (134, 66), 256: (50, 50, 2), 273: (102, 134, 169), 288: (50, 2, 89), 303: (55, 134, 0), 314: (2, 50, 2), 317: (169, 95), 335: (84, 165), 361: (169, 169, 188), 367: (50, 2), 397: (169, 188), 402: (55, 55, 169, 169), 448: (62, 95), 451: (169, 134), 454: (50, 2, 89, 120, 2), 464: (66, 66, 62, 62, 95), 472: (2, 66, 66), 473: (147, 2), 494: (50, 50, 84), 539: (77, 146), 541: (146, 49), 547: (89, 2), 548: (50, 50, 50, 2), 595: (50, 50, 66, 134), 606: (55, 187), 611: (89, 120, 84), 621: (147, 50, 50, 50, 2), 624: (55, 55, 169), 635: (66, 55, 55), 643: (66, 2, 2, 2), 651: (102, 134, 134), 670: (165, 48), 678: (55, 134, 103), 687: (147, 146), 690: (2, 89, 50, 50), 697: (120, 2, 89), 712: (2, 77), 732: (2, 50, 147), 733: (66, 147), 759: (2, 89, 50, 66), 760: (66, 62, 62), 775: (62, 66, 62, 62)}
NEW_FUSED={tag:seq for tag,seq in FUSED.items() if tag not in (194,250,273,361,397,401,402,451,624,651,726)}


def synthetic(args,base,tag,*,status=False,shift=13):
 p,selected,functions=r.synthetic(args,base,'call')
 # These controls use no constructor heap. Retain only their actual guest,
 # image and native stack input pages; the oracle maps its usual arenas.
 p={k:data for k,data in p.items() if not 0x79000000<=k<<12<0x7A000000
  and (not 0x78000000<=k<<12<0x78200000 or v.SP-0x2000<=k<<12<v.SP+0x1000)}
 r.put(p,r.CONTEXT+0x6070,r.CONTEXT if status else r.DATA+0x100)
 r.put(p,r.CONTEXT+0x60A8,r.DATA+0x200)
 def operand(address,operation,index):
  destination=20+index
  if operation in (2,134):word=r.word(4,destination,0)
  elif operation in (55,120):word=r.word(11,5,index*8)
  elif operation in (62,66):word=r.word(4,destination,-17 if operation==62 else 16)
  elif operation in (95,187):word=r.word(5,6,0)
  elif operation==102:word=r.word(0,destination,0)
  elif operation in (147,165):word=r.word(6,destination,0xBEEF if operation==147 else -17)
  elif operation==169:word=r.word(5,0,destination)
  else:word=6|(5<<8)|(destination<<16)|(shift<<24)
  r.record(p,address,operation,word,r.CONTEXT if status and operation==102 else r.ROOT+72 if operation==102 else 0)
 if tag in NEW_PRIMARY:
  operand(r.CODE,tag,0);count=2
 else:
  sequence=NEW_FUSED[tag];r.record(p,r.CODE,tag)
  for index,operation in enumerate(sequence):
   address=r.CODE+(index+1)*48;operand(address,operation,index)
   r.put(p,r.CODE+(len(sequence)-index-1)*8,address)
  count=len(sequence)+2
 r.record(p,r.CODE+(count-1)*48,189);r.descriptor(p,r.DESCRIPTOR,r.CODE,count)
 return p,selected,functions


def builtin_input(args,base,label):
 p,_,_=synthetic(args,base,2);target=r.DATA+0x100;entry=0x2EAE70
 old=0xFEDCBA9876543210;first=old;second=0x1020304050607080
 if label=='CAS_mismatch':first^=1<<48
 elif label=='CAS_zero':old=first=0;second=(1<<64)-1
 elif label=='CAS_max_new':second=(1<<64)-1
 elif label=='CAS_result_alias':target=r.CONTEXT+0x6080
 elif label=='CAS_argument_alias':target=r.CONTEXT+0x6090;old=first=target
 elif label=='CAS_image_control':target=base+0x3E1E80
 elif label.startswith('memset_'):
  entry=0x2EA98C;first=0xFEDCBA98765432AB
  if label=='memset_argument_alias':target=r.CONTEXT+0x6090;second=24
  elif label=='memset_result_alias':target=r.CONTEXT+0x6080;second=8
  else:second=int(label.split('_')[1])
  if second==4097:target=r.DATA+0xF80
 r.put(p,target,old);r.put(p,r.CONTEXT+0x6090,target)
 r.put(p,r.CONTEXT+0x6098,first);r.put(p,r.CONTEXT+0x60A0,second)
 return p,entry


def builtin_compare(args,base,label):
 p,entry=builtin_input(args,base,label);cpu,_=r.native(args,base,p,0,set(),entry=entry)
 result=r.alternative.run_runtime_imported_builtin(p,image_base=base,function_address=base+entry,context_address=r.CONTEXT)
 assert result==cpu.reg_read(v.arm.UC_ARM64_REG_X0)==v.u(p,r.CONTEXT+0x6080)
 startup.pages_equal(p,cpu)
 return dict(base=hex(base),label=label,entry=hex(entry),natural_return_SP_and_result_match=True,
  all_supplied_guest_image_pages_match=True,real_builtin_body_executed=True,native_snapshot_input=False)


def real_builtin_descriptor(args,base,p,selected,label):
 functions={base+0x2EA98C};saved=v.oracle.native
 def native(*a,**kw):
  capture=kw['host_imports'].copy();kw['host_imports']={}
  def observe(cpu,address):
   if address-base in capture:capture[address-base](cpu)
  kw['instruction_observer']=observe
  return saved(*a,**kw)
 try:
  v.oracle.native=native;cpu,expected=r.native(args,base,p,selected,functions)
 finally:v.oracle.native=saved
 calls=[]
 def imported(p,function,ctx,sp):
  active=v.u(p,ctx+8)
  calls.append((function,ctx,sp,_read_span(p,ctx,0x62D0),_read_span(p,active,16)))
  r.alternative.run_runtime_imported_builtin(p,image_base=base,function_address=function,context_address=ctx)
 result=r.alternative.execute_runtime_descriptor(p,image_base=base,descriptor_address=selected,
  context_address=r.CONTEXT,entry_stack_address=v.SP,call_import=imported)
 assert calls==expected and result.imported_calls==tuple(row[:3] for row in calls)
 assert result.status_word==int.from_bytes(cpu.mem_read(r.CONTEXT,4),'little')
 startup.pages_equal(p,cpu)
 return dict(base=hex(base),label=label,dispatches=result.steps,imported_calls=len(calls),
  natural_return_SP_and_status_match=True,all_guest_heap_image_pages_match=True,
  imported_context_active_frame_and_SP_match=True,real_builtin_bodies_executed=True,
  actual_ELF_nested_worker_descriptor=True,native_snapshot_input=False)


def negative_cases(args):
 rows=previous.negatives(args);base=0x122C0000
 def reject(label,tag=2,mutation=None,changes=None,builtin=None,fault=None):
  p,selected,_=synthetic(args,base,tag)
  if builtin:p,entry=builtin_input(args,base,builtin)
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=r.alternative._write_span;hits=[]
  def write(p,a,data):
   if fault(a,data):hits.append(a);raise RefillUnsupported('injected worker runtime write failure')
   return saved(p,a,data)
  kw=dict(image_base=base,context_address=r.CONTEXT)
  kw.update(dict(function_address=base+entry) if builtin else dict(descriptor_address=selected,entry_stack_address=v.SP,call_import=lambda *a:None))
  kw.update(changes or {})
  try:
   if fault:r.alternative._write_span=write
   try:(r.alternative.run_runtime_imported_builtin if builtin else r.alternative.execute_runtime_descriptor)(p,**kw)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted worker guard '+label)
  finally:r.alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,tag,word in (
  ('byte_register80',2,r.word(4,80,0)),('binary_register80',48,6|(5<<8)|(80<<16)),
  ('byte_store_register80',120,r.word(11,80,0)),('mask_register80',147,r.word(6,80,1)),
  ('unequal_branch_register80',187,r.word(80,6,0))):reject(label,tag,lambda p,word=word:r.put(p,r.CODE,word,4))
 for label,immediate in (('unequal_branch_forward_escape',32767),('unequal_branch_negative_escape',-2),('unequal_branch_loop',-1)):
  reject(label,187,lambda p,immediate=immediate:r.put(p,r.CODE,r.word(5,6,immediate),4),dict(max_steps=8))
 reject('byte_load_unmapped',2,lambda p:r.put(p,r.CONTEXT+0x6070,0x76000000))
 reject('byte_store_control',120,lambda p:r.put(p,r.CONTEXT+0x60A8,r.CONTEXT+15))
 reject('byte_store_code',120,lambda p:r.put(p,r.CONTEXT+0x60A8,r.CODE+47))
 for tag in (193,454,606):reject('new_fused_alias_'+str(tag),tag,lambda p:r.put(p,r.CODE,r.CODE))
 for label,changes in (
  ('builtin_unknown',dict(function_address=base+0x2EA9C4)),('builtin_zero_bound',dict(max_bytes=0)),
  ('builtin_boolean_bound',dict(max_bytes=True)),('builtin_small_bound',dict(max_bytes=7)),
  ('builtin_context_alias',dict(context_address=base+0x1000))):reject(label,changes=changes,builtin='CAS_match')
 for label,word in (('builtin_null',0),('builtin_unaligned',r.DATA+1),('builtin_overflow',(1<<64)-4),
  ('builtin_unmapped',0x76000000),('builtin_control',r.CONTEXT+8)):
  reject(label,mutation=lambda p,word=word:r.put(p,r.CONTEXT+0x6090,word),builtin='CAS_match')
 reject('builtin_reserved',changes=dict(reserved_regions=((r.DATA,r.DATA+0x1000),)),builtin='CAS_match')
 reject('memset_byte_bound',changes=dict(max_bytes=14),builtin='memset_15')
 for label,builtin,address in (('CAS_target_write_failure','CAS_match',r.DATA+0x100),
  ('CAS_result_write_failure','CAS_match',r.CONTEXT+0x6080),('memset_result_write_failure','memset_15',r.CONTEXT+0x6080)):
  reject(label,builtin=builtin,fault=lambda a,data,target=address:a==target)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negative_cases(args);rows=[];builtins=[];startup_rows=[]
 for base in (0x122C0000,0x775C205000):
  for tag in NEW_PRIMARY:
   profiles=['ordinary']
   if tag in (0,77,84,103,138,144,146):profiles.extend('shift_'+str(n) for n in (0,31,32,63,255))
   if tag in (48,49,50,74,89,105,147,153,165):profiles.extend(('overflow','alias'))
   if tag==2:profiles.append('status')
   if tag==120:profiles.append('page_edge')
   if tag==187:profiles.extend(('branch_equal','branch_different'))
   for profile in profiles:
    p,selected,functions=synthetic(args,base,tag,status=profile=='status',shift=int(profile[6:]) if profile.startswith('shift_') else 13)
    if profile=='overflow':
     r.put(p,r.CONTEXT+0x6078,0 if tag==153 else 0xFFFFFFFF7FFFFFFF);r.put(p,r.CONTEXT+0x6080,0x80000000)
    elif profile=='alias':
     word=v.u(p,r.CODE,4);mask=0xFF00 if tag in (147,165) else 0xFF0000
     r.put(p,r.CODE,(word&~mask)|(6<<(8 if tag in (147,165) else 16)),4)
    elif profile=='page_edge':r.put(p,r.CONTEXT+0x60A8,r.DATA+4095);r.put(p,r.CONTEXT+0x6078,0x100)
    elif profile.startswith('branch_'):
     p,selected,functions=previous.synthetic(args,base,profile)
     r.put(p,r.CODE+40,187);r.put(p,r.CODE+2*48+40,187)
    row=r.compare(args,base,p,selected,functions,f'primary_{tag}_{profile}');row['new_primary_control']=True;rows.append(row)
  for tag,sequence in NEW_FUSED.items():
   for status in ((False,True) if any(op in (2,102,134) for op in sequence) else (False,)):
    p,selected,functions=synthetic(args,base,tag,status=status)
    row=r.compare(args,base,p,selected,functions,f'fused_{tag}_'+('status' if status else 'ordinary'));row['new_fused_control']=True;rows.append(row)
  for tag in sorted(set(r.RECIPES)|set(previous.RECIPES)):
   p,selected,functions=(previous.synthetic if tag in previous.RECIPES else r.synthetic)(args,base,'fused_'+str(tag))
   row=r.compare(args,base,p,selected,functions,'existing_fused_'+str(tag),mutate=True);row['existing_fused_regression']=True;rows.append(row)
  for label in ('CAS_match','CAS_mismatch','CAS_zero','CAS_max_new','CAS_result_alias','CAS_argument_alias','CAS_image_control',
   'memset_0','memset_1','memset_7','memset_8','memset_15','memset_4097','memset_argument_alias','memset_result_alias'):
   builtins.append(builtin_compare(args,base,label))
  print('Full worker synthetic instructions and real builtins passed',hex(base),flush=True)
  initial=r.constructor.prepare(args,base);r.constructor.model(initial,base)
  for index in range(6):
   region=0x79800000+index*0x4000
   for step in (0,1):
    p={k:bytearray(data) for k,data in initial.items()};_write_span(p,region,bytes(0x4000));r.context(p)
    for i in range(8):r.put(p,base+0x3E2280+index*0x40+i*8,region+i*0x800)
    r.put(p,r.CONTEXT+0x6090,region);r.put(p,r.CONTEXT+0x6098,region+0x800 if step else 0)
    if step:_write_span(p,region,bytes(range(256))*8)
    selected=v.u(p,base+0x3E2220+index*16+step*8)
    rows.append(real_builtin_descriptor(args,base,p,selected,f'actual_nested_{index}_{step}'))
  startup.setup(initial,args)
  for sp,tid,label in ((v.SP,137,'startup_regression'),(v.SP-0xC80,1,'startup_relocated_regression')):
   startup_rows.append(startup.startup_compare(args,base,initial,sp,tid,label))
  print('Actual nested worker programs and startup regressions passed',hex(base),flush=True)
 evidence=dict(schema='vm9-alternative-worker-arithmetic-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_runtime_controls=len(rows),native_Python_builtin_controls=len(builtins),
  new_primary_controls=sum(row.get('new_primary_control',False) for row in rows),
  new_fused_controls=sum(row.get('new_fused_control',False) for row in rows),
  existing_fused_regression_controls=sum(row.get('existing_fused_regression',False) for row in rows),
  actual_ELF_nested_worker_controls=24,actual_B_startup_regression_controls=len(startup_rows),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=52,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,
  actual_CAS_and_memset_bodies_executed=True,full_B_worker_caller_composed=False,
  full_JNI_bootstrap_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,builtin_cases=builtins,startup_regressions=startup_rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Full worker runtime',len(rows),'builtins',len(builtins),'startup',len(startup_rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
