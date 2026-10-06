"""Live C-string append +0x2486b0 versus fresh native ELF execution.

Includes overlapping byte loops, poisoned moved realloc input, partial native
NULL failure and guest rollback. Allocation effects are explicit synthetic
providers, not the matching libc allocator implementation.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1
import vm9_objects as objects
from vm9_allocator import RefillUnsupported,_read_span,_write_span
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects,fields

LABELS=('fits','empty','fills_capacity','grows_long','full_empty','source_cross_page',
        'object_cross_page','self_source','self_source_suffix','source_in_unused_space',
        'inplace_alias_growth','round_realloc_fails','both_reallocs_fail','zero_capacity')


def fixture(label,base):
 p=oracle.fresh_pages();obj=oracle.GUEST+(0x1FF0 if label=='object_cross_page' else 0x1000)
 pointer=oracle.GUEST+0x2800;source=oracle.GUEST+0x3000
 capacity,old,data=8,b'abc',b'de'
 if label=='empty':data=b''
 if label=='fills_capacity':data=b'12345'
 if label in ('grows_long','round_realloc_fails','both_reallocs_fail'):data=b'x'*97
 if label=='full_empty':old,data=b'abcdefgh',b''
 if label=='source_cross_page':source,data=oracle.GUEST+0x3FFD,b'long_suffix'
 if label in ('self_source','self_source_suffix','source_in_unused_space','inplace_alias_growth'):capacity=16
 if label=='zero_capacity':capacity,old,data=0,b'',b'xyz'
 _write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little'))
 fields(p,obj+8,capacity,len(old),pointer)
 _write_span(p,pointer,old+b'\0'+bytes(64-len(old)-1))
 _write_span(p,source,data+b'\0')
 if label in ('self_source','inplace_alias_growth'):source=pointer
 if label=='self_source_suffix':source=pointer+1
 if label=='source_in_unused_space':source=pointer+12;_write_span(p,source,b'XYZ\0')
 return p,obj,pointer,source


def case(library,base,label):
 p,obj,pointer,source=fixture(label,base)
 failures=(0,) if label=='round_realloc_fails' else (0,1) if label=='both_reallocs_fail' else ()
 options=dict(blocks=[(pointer,64)],failures=failures,inplace=label=='inplace_alias_growth')
 native_effects=Effects(**options);model_effects=Effects(**options)
 native_effects.next=model_effects.next=oracle.GUEST+0x6000
 result,memory,_,_=oracle.native(library,base,0x2486B0,[obj,source],p,
  malloc_handler=lambda cpu,size:native_effects.native(cpu,'malloc',size),
  host_imports={0x347FA0:lambda cpu:native_effects.native(cpu,'free',pointer=cpu.reg_read(UC_ARM64_REG_X0)),
    0x348320:lambda cpu:native_effects.native(cpu,'realloc',cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))},
  instruction_limit=100000)
 actual=objects.append_cstring_object(p,object_address=obj,source_address=source,
  allocate=model_effects.malloc,reallocate=model_effects.realloc,free=model_effects.free)
 got=oracle.flatten(p)[:0xA000]
 if got!=memory:
  offset=next(i for i,(x,y) in enumerate(zip(got,memory)) if x!=y)
  raise AssertionError((label,hex(offset),got[offset],memory[offset]))
 assert result==actual==obj and native_effects.calls==model_effects.calls and native_effects.blocks==model_effects.blocks
 return dict(case=label,image_base=hex(base),guest_object_payload_poison_and_padding_match=True,
  defined_native_return_matches=True,ordered_allocator_effects_and_live_blocks_match=True,
  allocator_operations=[call[0] for call in model_effects.calls],
  final_capacity=int.from_bytes(_read_span(p,obj+8,4),'little'),
  final_length=int.from_bytes(_read_span(p,obj+12,4),'little'),
  modeled_null_failure_preserves_partial_native_writes=label=='both_reallocs_fail')


def rejection_cases():
 rows=[]
 for label in ('negative_length','capacity_below_length','missing_source','missing_destination',
               'source_unterminated','bound_exceeded','invalid_bound','late_realloc_provider_failure'):
  p,obj,pointer,source=fixture('grows_long',0x122C0000)
  effects=Effects(blocks=[(pointer,64)]);effects.next=oracle.GUEST+0x6000
  bound=0x100000
  if label=='negative_length':fields(p,obj+8,8,0xFFFFFFFF,pointer)
  if label=='capacity_below_length':fields(p,obj+8,2,3,pointer)
  if label=='missing_source':source=oracle.GUEST+0x10000
  if label=='missing_destination':obj=oracle.GUEST+0x10000
  if label=='source_unterminated':source=oracle.GUEST+0x9FFB;_write_span(p,source,b'a'*5);p.pop((oracle.GUEST+0xA000)>>12)
  if label=='bound_exceeded':bound=16
  if label=='invalid_bound':bound=-1
  realloc=effects.realloc
  if label=='late_realloc_provider_failure':
   def realloc(staged,ptr,size):
    _write_span(staged,ptr,b'changed');raise RefillUnsupported('injected late realloc failure')
  before={key:bytes(value) for key,value in p.items()}
  try:objects.append_cstring_object(p,object_address=obj,source_address=source,
   allocate=effects.malloc,reallocate=realloc,free=effects.free,max_bytes=bound)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError((label,'expected rejection'))
  assert before=={key:bytes(value) for key,value in p.items()}
  rows.append(dict(case=label,rejected=True,all_guest_pages_unchanged=True))
 return rows


def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 rows=[case(args.library,base,label) for base in (0x122C0000,0x775C205000) for label in LABELS]
 rejected=rejection_cases()
 report=dict(schema='vm9-cstring-append-native-v1',sample_sha256=oracle.LIBRARY_SHA256,cases=rows,
  rejection_cases=rejected,native_controls=len(rows),rollback_checks=len(rejected),
  native_input_snapshot_used=False,explicit_allocator_effects=True,matching_libc_realloc_restored=False,
  full_registry_caller_verified=False,complete_python_medusa=False)
 args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('cstring append',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
