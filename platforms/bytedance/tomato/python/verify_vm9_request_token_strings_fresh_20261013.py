"""Actual nested format, sized constructor and hidden-output pair consumers.

Matching-libc vsnprintf executes natively. Fresh synthetic inputs and explicit
allocator effects verify new wrappers; no accepted helper group is repeated.
"""
from pathlib import Path
import argparse,hashlib,json
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_shared_reference import fixture as formatter_fixture,TLS
from verify_vm9_strings import Effects
from verify_vm9_libc_mapping import LIBC_SHA256
import vm9_request_token_vm as model
import vm9_configuration_init as configuration
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x3800
DEST=G+0x1800;FIRST=G+0x1900;SECOND=G+0x1A00;FMT=G+0x3500
FORMAT_CASES=('signed','minimum','wide_W2','long_string','percent','empty','third_argument','realloc_failure')
SIZED_CASES=('binary','empty','negative','wrap','wide_W2','NULL_malloc','cross_page')
PAIR_CASES=('binary','first_empty','second_empty','first_alias','second_alias','NULL_malloc','growth_failure','cross_page')


def word(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def string(p,a,base,data,pointer):
 word(p,a,base+0x34F5F8);word(p,a+8,len(data)+1,4);word(p,a+12,len(data),4);word(p,a+16,pointer)
 _write_span(p,pointer,data+b'\0')


def fixture(library,libc,base,kind,label):
 p=formatter_fixture(library,base,libc) if kind=='format' else {**oracle.image_pages(library,base),**oracle.fresh_pages()}
 destination=DEST;failures=();blocks={}
 if kind=='format':
  wrapper=0x288B74;target=0x248908;value=0xFFFFFFFF;fmt=b'%d/%s';tail=b'fixture';extra=7
  if label=='minimum':value=0x80000000
  elif label=='wide_W2':value=0xABCDEF0180000001
  elif label=='long_string':tail=b'x'*80
  elif label=='percent':fmt=b'%%/%d/%s/%%'
  elif label=='empty':fmt=b''
  elif label=='third_argument':fmt=b'%d/%s/%u'
  elif label=='realloc_failure':failures=(3,4,5)
  string(p,destination,base,b'',G+0x2000);blocks={G+0x2000:8};word(p,destination+8,8,4)
  _write_span(p,FMT,fmt+b'\0');_write_span(p,G+0x3000,tail+b'\0')
  words=(base+target,destination,FMT,value,G+0x3000,extra)
 elif kind=='sized':
  wrapper=0x288B8C;target=0x2481FC;length=6;source=G+0x3000
  if label=='empty':length=0
  elif label=='negative':length=0x80000000
  elif label=='wrap':length=0xFFFFFFFF
  elif label=='wide_W2':length=0xBADC0FFE00000006
  elif label=='NULL_malloc':failures=(0,)
  elif label=='cross_page':destination=G+0x1FF8
  _write_span(p,source,b'a\0b\xffCD\0');words=(base+target,destination,source,length)
 else:
  wrapper=0x288BA0;target=0x248780;first=FIRST;second=SECOND;left=b'a\0b';right=b'XYZ\xff'
  if label=='first_empty':left=b''
  elif label=='second_empty':right=b''
  elif label=='first_alias':destination=first
  elif label=='second_alias':destination=second
  elif label=='NULL_malloc':failures=(0,)
  elif label=='growth_failure':failures=(1,2,3)
  elif label=='cross_page':destination=G+0x1FF8
  string(p,first,base,left,G+0x2800);string(p,second,base,right,G+0x2C00)
  blocks={G+0x2800:len(left)+1,G+0x2C00:len(right)+1}
  words=(base+target,destination,first,second)
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in words)+b'\xA5'*16)
 return p,wrapper,blocks,failures


def exports(libc):
 with libc.open('rb') as f:
  return {s.name:0x51000000+s['st_value'] for section in ELFFile(f).iter_sections()
   if section['sh_type']=='SHT_DYNSYM' for s in section.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}


def original(library,libc,base,p,wrapper,effects,table):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 wake=[];imports={0x347FA0:lambda c:effects.native(c,'free',pointer=c.reg_read(arm.UC_ARM64_REG_X0)),
  0x348320:lambda c:effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))}
 def vsnprintf(c):c.reg_write(arm.UC_ARM64_REG_PC,table['vsnprintf'])
 if wrapper==0x288B74:
  imports[0x347F70]=vsnprintf
  for span in ((TLS,0xB00),(0x510DE930,16),(0x510E0200,0x800)):watch[span]=None
 def syscall(c,n):
  assert n==98;aa=[c.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)]
  assert aa[1]==129;wake.append(aa);return 0
 returned,memory,_,_=oracle.native(library,base,wrapper,[PACKED],p,
  libc=libc if wrapper==0x288B74 else None,host_imports=imports,
  malloc_handler=lambda c,n:effects.native(c,'malloc',n),syscall_handler=syscall,
  extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TLS},observed_memory=watch,instruction_limit=300000)
 return returned,memory,watch,wake


def red(library,libc,table):
 assert not hasattr(model,'apply_token_string_transform_callback');rows=[]
 for base in BASES:
  p,wrapper,blocks,failures=fixture(library,libc,base,'format','signed')
  returned,memory,watch,wake=original(library,libc,base,p,wrapper,Effects(blocks=blocks),table)
  assert returned==0 and int.from_bytes(memory[0x180C:0x1810],'little')==10
  rows.append(dict(image_base=hex(base),original_format_consumer_returned=True,
   prior_nested_transform_consumer_missing=True,matching_libc_vsnprintf_executed=True,native_snapshot_input=False))
 return rows


def compare(library,libc,base,kind,label,table):
 p,wrapper,blocks,failures=fixture(library,libc,base,kind,label)
 expected=Effects(blocks=blocks,failures=failures);returned,memory,watch,expected_wake=original(library,libc,base,p,wrapper,expected,table)
 actual=Effects(blocks=blocks,failures=failures);wake=[]
 def prepare(p):
  configuration.prepare_bionic_format_locale(p,once_address=0x510DE938,key_address=0x510DE930,
   generation_table=0x510E0200,thread_pointer=TLS,wake=lambda p,*a:wake.append(list(a)) or 0)
 result=model.apply_token_string_transform_callback(p,wrapper_offset=wrapper,argument_block_address=PACKED,
  image_base=base,entry_stack_address=G+0xEF00,allocate=actual.malloc,reallocate=actual.realloc,free=actual.free,prepare_format=prepare)
 got=_read_span(p,G,0xA000)
 assert got==memory,(kind,label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(got,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(kind,label,'ELF/TLS')
 assert actual.calls==expected.calls and actual.blocks==expected.blocks and wake==expected_wake,(kind,label,'effects')
 compared=kind=='pair' or kind=='sized' and label not in ('negative','wrap')
 if compared:assert result&0xFFFFFFFFFFFFFFFF==returned&0xFFFFFFFFFFFFFFFF,(kind,label,result,returned)
 print('PASS nested string transform',hex(base),kind,label,flush=True)
 return dict(image_base=hex(base),kind=kind,case=label,original_consumer_returned=True,
  all_guest_ELF_TLS_and_packed_padding_equal=True,ordered_allocator_free_realloc_locale_effects_equal=True,
  matching_libc_vsnprintf_executed=kind=='format',native_result_compared=compared,native_snapshot_input=False)


def guards(library,libc):
 rows=[]
 for label in ('bad_target','wrong_wrapper','unmapped_source','unmapped_output','sized_bound','format_conversion','format_NULL','pair_spill_alias','pair_bound','pair_live_spill_alias'):
  kind='format' if label.startswith('format') else 'pair' if label.startswith('pair') else 'sized'
  p,wrapper,blocks,failures=fixture(library,libc,BASES[0],kind,'signed' if kind=='format' else 'binary');effect=Effects(blocks=blocks)
  kw=dict(wrapper_offset=wrapper,argument_block_address=PACKED,image_base=BASES[0],entry_stack_address=G+0xEF00,
   allocate=effect.malloc,reallocate=effect.realloc,free=effect.free)
  if label=='bad_target':word(p,PACKED,BASES[0]+0x2483E0)
  elif label=='wrong_wrapper':kw['wrapper_offset']=0x288B4C
  elif label=='unmapped_source':word(p,PACKED+16,0x64000000)
  elif label=='unmapped_output':word(p,PACKED+8,0x64000000)
  elif label=='sized_bound':kw['max_bytes']=5
  elif label=='format_conversion':_write_span(p,FMT,b'%x\0')
  elif label=='format_NULL':word(p,PACKED+16,0)
  elif label=='pair_spill_alias':word(p,PACKED+8,G+0xEE00)
  elif label=='pair_bound':kw['max_bytes']=2
  elif label=='pair_live_spill_alias':
   def redirected(p,n):
    result=effect.malloc(p,n);word(p,SECOND+16,G+0xEE00);return result
   kw['allocate']=redirected
  before={k:bytes(v) for k,v in p.items()}
  try:model.apply_token_string_transform_callback(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_rollback_verified=False))
 return rows


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
 p.add_argument('--libc',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--group',choices=('red','consumer','guards','all'),default='all');args=p.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256 and hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 table=exports(args.libc)
 e=dict(schema='vm9-request-token-strings-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  libc_sha256=LIBC_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library,args.libc,table)
 if args.group in ('consumer','all'):e['cases']=[compare(args.library,args.libc,b,k,n,table) for b in BASES
  for k,names in (('format',FORMAT_CASES),('sized',SIZED_CASES),('pair',PAIR_CASES)) for n in names]
 if args.group in ('guards','all'):e['negative_cases']=guards(args.library,args.libc)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested string transforms',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
