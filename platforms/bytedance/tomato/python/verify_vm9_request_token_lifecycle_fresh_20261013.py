"""Actual nested StringObject clone, default constructor and cleanup consumers.

Reuse accepted object owners. Independently constructed inputs and explicit
allocation/free effects compare new wrappers; accepted helper groups are not run.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_token_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000)
PACKED=oracle.GUEST+0x2400;DEST=oracle.GUEST+0x1800;SOURCE=oracle.GUEST+0x1900
PAYLOAD=oracle.GUEST+0x3000
CASES=('clone_binary','clone_empty','clone_negative','clone_wrap','clone_self',
 'clone_source_pointer_alias','clone_cross_page','clone_malloc_NULL','clone_live_source',
 'default','default_cross_page','default_malloc_NULL','destroy','destroy_NULL',
 'delete','delete_NULL','free','free_NULL')


def word(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))


def fixture(library,base,label):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
 destination=DEST;source=SOURCE;pointer=PAYLOAD;length=6;target=0x2483E0;wrapper=0x288B4C
 if label=='clone_empty':length=0
 elif label=='clone_negative':length=0x80000000
 elif label=='clone_wrap':length=0xFFFFFFFF
 elif label=='clone_self':destination=source
 elif label=='clone_source_pointer_alias':destination=SOURCE+16
 elif label in ('clone_cross_page','default_cross_page'):destination=oracle.GUEST+0x1FF8
 if label.startswith('default'):target=0x2481AC;wrapper=0x288B68
 elif label.startswith('destroy'):target=0x2484B8;wrapper=0x288B68
 elif label.startswith('delete'):target=0x2484FC;wrapper=0x288B68
 elif label.startswith('free'):target=0x32A264;wrapper=0x288B5C;destination=0 if label=='free_NULL' else PAYLOAD
 _write_span(p,PAYLOAD,b'a\0b\xffCD\0')
 _write_span(p,PAYLOAD+0x100,b'XYZ\0ef\0')
 word(p,source,base+0x34F5F8);word(p,source+8,7,4);word(p,source+12,length,4);word(p,source+16,pointer)
 if label.startswith(('destroy','delete')):
  word(p,destination,base+0x34F5F8);word(p,destination+8,7,4);word(p,destination+12,6,4)
  word(p,destination+16,0 if label.endswith('NULL') else PAYLOAD)
 _write_span(p,PACKED,(base+target).to_bytes(8,'little')+destination.to_bytes(8,'little')+source.to_bytes(8,'little')+b'\xA5'*8)
 return p,wrapper,target,source


def original(library,base,p,wrapper,label,source):
 events=[];allocation=oracle.Allocator()
 def malloc(cpu,n):
  result=0 if label.endswith('malloc_NULL') else allocation.take(n)
  events.append(['malloc',n,result])
  if label=='clone_live_source':cpu.mem_write(source+16,(PAYLOAD+0x100).to_bytes(8,'little'))
  return result
 def free(cpu):events.append(['free',cpu.reg_read(arm.UC_ARM64_REG_X0)]);return 0
 watch={(page<<12,4096):None for page in p if not oracle.GUEST<=page<<12<oracle.GUEST+oracle.GUEST_SIZE}
 returned,memory,_,_=oracle.native(library,base,wrapper,[PACKED],p,malloc_handler=malloc,
  host_imports={0x347FA0:free},observed_memory=watch,instruction_limit=20000)
 return returned,memory,watch,events


def red(library):
 assert not hasattr(model,'apply_token_string_lifecycle_callback')
 rows=[]
 for base in BASES:
  p,wrapper,target,source=fixture(library,base,'clone_binary')
  returned,memory,watch,events=original(library,base,p,wrapper,'clone_binary',source)
  assert returned==oracle.GUEST+0x4000 and events==[['malloc',7,returned]]
  assert memory[0x4000:0x4007]==b'a\0b\xffCD\0'
  rows.append(dict(image_base=hex(base),original_clone_consumer_returned=True,
   prior_nested_lifecycle_consumer_missing=True,native_snapshot_input=False))
 return rows


def compare(library,base,label):
 p,wrapper,target,source=fixture(library,base,label)
 returned,memory,watch,expected=original(library,base,p,wrapper,label,source)
 events=[];allocation=oracle.Allocator()
 def allocate(p,n):
  result=0 if label.endswith('malloc_NULL') else allocation.model(p,n)
  events.append(['malloc',n,result])
  if label=='clone_live_source':word(p,source+16,PAYLOAD+0x100)
  return result
 def free(p,pointer):events.append(['free',pointer]);return 0
 result=model.apply_token_string_lifecycle_callback(p,wrapper_offset=wrapper,
  argument_block_address=PACKED,image_base=base,allocate=allocate,free=free)
 assert _read_span(p,oracle.GUEST,0xA000)==memory,(hex(base),label,'guest')
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items())
 assert events==expected,(label,'effects',events,expected)
 compared=target in (0x2483E0,0x2481AC)
 if compared:assert result==returned,(label,result,returned)
 print('PASS nested lifecycle',hex(base),label,flush=True)
 return dict(image_base=hex(base),case=label,wrapper_offset=hex(wrapper),target_offset=hex(target),
  original_consumer_returned=True,all_guest_ELF_and_packed_padding_equal=True,
  ordered_allocator_free_effects_equal=True,native_return_x0_compared=compared,native_snapshot_input=False)


def guards(library):
 rows=[]
 for label in ('unmapped_source','unmapped_destination','payload_bound','invalid_bound',
  'wrong_wrapper','bad_target','invalid_allocation','free_failure'):
  base=BASES[0];profile='delete' if label=='free_failure' else 'clone_binary'
  p,wrapper,target,source=fixture(library,base,profile);allocation=oracle.Allocator()
  kw=dict(wrapper_offset=wrapper,argument_block_address=PACKED,image_base=base,allocate=allocation.model,free=lambda p,a:0)
  if label=='unmapped_source':word(p,PACKED+16,0x64000000)
  elif label=='unmapped_destination':word(p,PACKED+8,0x64000000)
  elif label=='payload_bound':kw['max_payload_bytes']=5
  elif label=='invalid_bound':kw['max_payload_bytes']=-1
  elif label=='wrong_wrapper':kw['wrapper_offset']=0x288B8C
  elif label=='bad_target':word(p,PACKED,base+0x248684)
  elif label=='invalid_allocation':kw['allocate']=lambda p,n:0x64000000
  elif label=='free_failure':
   def failure(p,a):_write_span(p,PAYLOAD,b'bad');raise RefillUnsupported('provider failed')
   kw['free']=failure
  before={k:bytes(v) for k,v in p.items()}
  try:model.apply_token_string_lifecycle_callback(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_rollback_verified=False))
 return rows


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--group',choices=('red','consumer','guards','all'),default='all');args=p.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 e=dict(schema='vm9-request-token-lifecycle-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library)
 if args.group in ('consumer','all'):e['cases']=[compare(args.library,b,n) for b in BASES for n in CASES]
 if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested lifecycle',args.group,e['native_Python_controls'],e['rollback_guards'])


if __name__=='__main__':main()
