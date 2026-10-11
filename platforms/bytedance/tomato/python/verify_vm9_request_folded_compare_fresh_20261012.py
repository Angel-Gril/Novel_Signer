"""Fresh actual +0x2765c4 folded comparison and +0x285c1c wrapper.

Both real warm singleton getters execute. Guest folding bytes drive results;
synthetic inputs and explicit getter services are independent of native output.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_registry as registry
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1400;SP=G+0xEF00
REFERENCE=G+0x7000;SINGLETON=G+0x7200
PROFILES=(
 ('zero_length',dict(first=b'',second=b'',length=0,unmapped=True)),
 ('ASCII_fold',dict(first=b'AbCdE',second=b'aBcDe',length=5)),
 ('negative_difference',dict(first=b'a',second=b'z',length=1)),
 ('positive_difference',dict(first=b'z',second=b'a',length=1)),
 ('embedded_NUL',dict(first=b'Ab\0tail',second=b'aB\0different',length=64)),
 ('binary',dict(first=bytes((128,255,1)),second=bytes((128,127,1)),length=3)),
 ('prefix_limit',dict(first=b'abX',second=b'abY',length=2)),
 ('cross_page',dict(first=b'AbCdE',second=b'aBcDe',length=5,cross_page=True)),
 ('first_field_only',dict(first=b'a',second=b'A',length=1,first_field=1)),
 ('second_field_only',dict(first=b'a',second=b'A',length=1,second_field=1)),
 ('mutated_guest_table',dict(first=b'A',second=b'a',length=1,mutate_table=True)),
 ('full_uint64_length_early_NUL',dict(first=b'',second=b'',length=(1<<64)-1)))


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fresh(library,base,profile):
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 w(p,base+0x3D1680,1,1);w(p,base+0x3D1678,REFERENCE)
 w(p,REFERENCE,SINGLETON);w(p,REFERENCE+8,0);_write_span(p,SINGLETON,bytes(136))
 w(p,SINGLETON+16,profile.get('first_field',0));w(p,SINGLETON+24,profile.get('second_field',0))
 first,second=(G+0x2FFD,G+0x3FFC) if profile.get('cross_page') else (G+0x2000,G+0x2400)
 _write_span(p,first,profile['first']+b'\0');_write_span(p,second,profile['second']+b'\0')
 if profile.get('unmapped'):first=second=0x66000000
 if profile.get('mutate_table'):w(p,base+0xA5BB7+ord('A'),7,1);w(p,base+0xA5BB7+ord('a'),7,1)
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x2765C4,first,second,profile['length']))+b'\xa5'*8)
 return p,first,second


def native(library,base,p,profile,wrapper,first,second):
 services=Services();visits=[]
 helper_sp=SP-(16 if wrapper else 0)
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 if profile['length']:observed[helper_sp-0x40-0xA0,8]=None
 def watch(c,pc):
  if pc==base+0x161068:visits.append(c.reg_read(arm.UC_ARM64_REG_SP))
 result,memory,_,_=oracle.native(library,base,0x285C1C if wrapper else 0x2765C4,
  [PACKED] if wrapper else [first,second,profile['length']],p,real_singletons=True,thread_id=137,
  malloc_handler=services.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
 assert visits==([helper_sp-0x40]*2 if profile['length'] else [])
 return result,memory,observed,visits,services


def compare(library,base,label,profile,wrapper):
 p,first,second=fresh(library,base,profile)
 result,memory,observed,visits,expected=native(library,base,p,profile,wrapper,first,second)
 actual=Services();calls=[];helper_sp=SP-(16 if wrapper else 0)
 def forbidden(*a,**kw):raise AssertionError('explicit warm singleton became cold')
 def getter(p,sp):
  calls.append(sp)
  return registry.get_singleton136_reference(p,entry_stack_address=sp,image_base=base,
   allocate=actual.malloc,free=actual.free,read_clock=forbidden,get_tls=forbidden,
   initialize_registry=forbidden,broadcast=forbidden,thread_id=137).wrapper_address
 out=objects.compare_folded_cstrings(p,first_address=first,second_address=second,
  length=profile['length'],entry_stack_address=helper_sp,image_base=base,get_singleton=getter)
 if wrapper:w(p,PACKED+32,out,4)
 assert out&0xFFFFFFFF==result&0xFFFFFFFF and _read_span(p,G,0xA000)==memory,(label,wrapper,'result/payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),(label,wrapper,'ELF/getter scratch')
 assert calls==visits and expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
 print('PASS',hex(base),'folded compare',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
  packed_u32_result_and_full_guest_payload_match=True,all_ELF_pages_and_getter_scratch_match=True,
  real_singleton_getter_order_and_SP_match=True,guest_folding_table_used=True,
  zero_length_skips_getters_and_pointer_reads=profile['length']==0,native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for label,profile in PROFILES:
    for wrapper in (False,True):cases.append(compare(args.library,base,label,profile,wrapper))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_getter','getter_exception','second_getter_exception','both_environment_fields',
                 'cached_first_field','missing_first','length_bound','unaligned_stack'):
    profile=dict(first=b'abc',second=b'ABC',length=3)
    if label in ('both_environment_fields','cached_first_field'):profile.update(first_field=1,second_field=1)
    p,first,second=fresh(args.library,base,profile);calls=[]
    def getter(p,sp):
     calls.append(sp);w(p,PACKED+40,len(calls))
     if label=='getter_exception' or label=='second_getter_exception' and len(calls)==2:
      raise RefillUnsupported('injected folded comparison getter failure')
     if label=='cached_first_field' and len(calls)==2:w(p,SINGLETON+16,0)
     return REFERENCE
    kw=dict(first_address=first,second_address=second,length=3,entry_stack_address=SP,image_base=base,
     get_singleton=None if label=='missing_getter' else getter)
    if label=='missing_first':kw['first_address']=0x66000000
    elif label=='length_bound':kw['max_bytes']=1
    elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
    before={k:bytes(v) for k,v in p.items()}
    try:objects.compare_folded_cstrings(p,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS folded comparison rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
