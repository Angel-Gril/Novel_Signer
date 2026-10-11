"""Original JNI reference field/method/cleanup helpers with synthetic services.

Synthetic member inputs exercise the original JNI table reads.
All payload/image pages, returned references, status bytes and call order are
compared. This verifies component behavior with no Android JVM or snapshots.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_jni_environment as environment
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;ENV=G+0x2000;TABLE=G+0x2800;OBJ=G+0x1400;NAME=G+0x1500;SIGNATURE=G+0x1600
STATUS=G+0x1700;CLS=G+0x1800;MEMBER=G+0x1900;RETURNED=G+0x1A00;SP=G+0xEF00
NAMES={0xD0:'PushLocalFrame',0x720:'ExceptionCheck',0x88:'ExceptionClear',0xF8:'GetObjectClass',
 0x2F0:'GetFieldID',0x2F8:'GetObjectField',0x108:'GetMethodID',0x118:'CallObjectMethodV',
 0xB8:'DeleteLocalRef',0xB0:'DeleteGlobalRef',0x718:'DeleteWeakGlobalRef',0x740:'GetObjectRefType'}
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def fresh(library,base,kind):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages());w(p,ENV,TABLE)
 _write_span(p,NAME,b'fixture_member\0');_write_span(p,SIGNATURE,(b'[B' if kind=='field' else b'()[B')+b'\0')
 for slot in NAMES:w(p,TABLE+slot,G+0xF600+slot//2)
 return p
class Services:
 def __init__(self,kind,checks,*,push=0,cls=CLS,member=MEMBER,returned=RETURNED,ref_kind=1):
  self.kind=kind;self.checks=list(checks);self.push=push;self.cls=cls;self.member=member;self.returned=returned;self.ref_kind=ref_kind;self.events=[]
 def call(self,slot,args,read):
  self.events.append([NAMES[slot],*args]);assert args[0]==ENV
  if slot==0xD0:assert args==(ENV,3);return self.push&0xFFFFFFFF
  if slot==0x720:assert self.checks;return self.checks.pop(0)&0xFFFFFFFF
  if slot==0xF8:assert args==(ENV,OBJ);return self.cls
  if slot in (0x108,0x2F0):assert args==(ENV,CLS,NAME,SIGNATURE);return self.member
  if slot==0x2F8:assert args==(ENV,OBJ,MEMBER);return self.returned
  if slot==0x118:
   assert args[:3]==(ENV,OBJ,MEMBER) and len(args)==4
   va=read(args[3],32);assert int.from_bytes(va[:8],'little')==SP
   assert int.from_bytes(va[8:16],'little')==SP-0x70 and int.from_bytes(va[16:24],'little')==SP-0x90
   assert va[24:]==(-24).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
   return self.returned
  if slot==0x740:return self.ref_kind
  assert slot in (0x88,0xB8,0xB0,0x718);return 0
 def model(self,p,fn,args):
  slot=(fn-(G+0xF600))*2;return self.call(slot,args,lambda a,n:_read_span(p,a,n))
 def imports(self,base):
  counts={0xD0:2,0x720:1,0x88:1,0xF8:2,0x108:4,0x2F0:4,0x118:4,0x2F8:3,0xB8:2,0xB0:2,0x718:2,0x740:2}
  def make(slot):
   return lambda c:self.call(slot,tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(counts[slot])),lambda a,n:bytes(c.mem_read(a,n)))
  return {G+0xF600+slot//2-base:make(slot) for slot in NAMES}
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
 assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 field=environment.read_java_reference_field;method=environment.invoke_no_argument_java_reference_method;release=environment.release_java_reference
 rows=[];guards=[]
 profiles=[('success',(0,0,0),{}),('NULL_environment',(),dict(env=0)),('NULL_object',(0,0),dict(obj=0)),
  ('NULL_name',(0,0),dict(name=0)),('NULL_signature',(0,0),dict(signature=0)),('NULL_status_pointer',(0,0,0),dict(status=0)),
  ('push_failure',(1,),dict(push=-1)),('initial_exception',(1,1),{}),('class_NULL',(0,0),dict(cls=0)),
  ('class_exception',(0,1,1),{}),('member_NULL',(0,0,0),dict(member=0)),('returned_NULL',(0,0,0),dict(returned=0)),
  ('final_exception',(0,0,1),{}),('exception_high_word_ignored',(0x100,0x100,0x100),{}),('final_exception_low_FF',(0,0,-1),{})]
 for base in (0x122C0000,0x775C205000):
  for kind,entry,op in (('field',0x26FA00,field),('method',0x26F650,method)):
   for label,checks,options in profiles:
    if kind=='method' and label=='NULL_signature':continue
    p=fresh(a.library,base,kind);kw=dict(options);env=kw.pop('env',ENV);obj=kw.pop('obj',OBJ);name=kw.pop('name',NAME);sig=kw.pop('signature',SIGNATURE);status=kw.pop('status',STATUS)
    expected=Services(kind,checks,**kw);actual=Services(kind,checks,**kw)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    result,memory,_,_=oracle.native(a.library,base,entry,[env,status,obj,name,sig],p,host_imports=expected.imports(base),observed_memory=observed,instruction_limit=20000)
    output=op(p,entry_stack_address=SP,environment_pointer=env,status_address=status,object_reference=obj,name_address=name,signature_address=sig,invoke_jni=actual.model)
    assert output.reference==result and _read_span(p,G,0xA000)==memory,(kind,label)
    for (address,n),data in observed.items():assert _read_span(p,address,n)==data
    assert actual.events==expected.events and not actual.checks and not expected.checks,(kind,label,'ordered JNI')
    if status:assert u(p,status,1)==(output.status_byte if env else 0xA5)
    rows.append(dict(case=label,kind=kind,image_base=hex(base),original_body_naturally_returned=True,
     guest_payload_and_image_pages_match=True,returned_reference_and_status_byte_match=True,all_ordered_JNI_services_match=True,JNI_calls=len(actual.events),native_snapshot_input=False))
    print('PASS',hex(base),kind,label,flush=True)
  for ref_kind in (0,1,2,3,4,0x100000001):
   for env,ref in ((ENV,OBJ),(0,OBJ),(ENV,0)) if ref_kind==1 else ((ENV,OBJ),):
    p=fresh(a.library,base,'field');expected=Services('release',(),ref_kind=ref_kind);actual=Services('release',(),ref_kind=ref_kind)
    _,memory,_,_=oracle.native(a.library,base,0x26F1D0,[env,ref],p,host_imports=expected.imports(base),instruction_limit=20000)
    release(p,environment_pointer=env,reference=ref,invoke_jni=actual.model)
    assert _read_span(p,G,0xA000)==memory and actual.events==expected.events
    rows.append(dict(case='release_'+str(ref_kind)+'_'+str(bool(env))+'_'+str(bool(ref)),kind='release',image_base=hex(base),original_body_naturally_returned=True,
     guest_payload_and_image_pages_match=True,returned_reference_and_status_byte_match=None,release_effects_match=True,all_ordered_JNI_services_match=True,JNI_calls=len(actual.events),native_snapshot_input=False))
 for kind,op in (('field',field),('method',method)):
  def reject(label,change=None,**changes):
   p=fresh(a.library,0x122C0000,kind)
   if change:change(p)
   before={k:bytes(v) for k,v in p.items()};services=Services(kind,(0,0,0))
   kw=dict(entry_stack_address=SP,environment_pointer=ENV,status_address=STATUS,object_reference=OBJ,name_address=NAME,signature_address=SIGNATURE,invoke_jni=services.model);kw.update(changes)
   try:op(p,**kw)
   except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
   else:raise AssertionError(label+' accepted')
   assert before=={k:bytes(v) for k,v in p.items()}
   guards.append(dict(kind=kind,case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
  reject('unaligned_stack',entry_stack_address=SP-1);reject('negative_environment',environment_pointer=-1)
  reject('missing_JNI',invoke_jni=None);reject('missing_class_method',change=lambda p:w(p,TABLE+0xF8,0))
  reject('missing_value_method_after_lookup',change=lambda p:w(p,TABLE+(0x2F8 if kind=='field' else 0x118),0))
  reject('unsupported_primitive_signature',change=lambda p:_write_span(p,SIGNATURE,(b'I' if kind=='field' else b'()I')+b'\0'))
  if kind=='method':
   reject('NULL_signature_read_before_environment',signature_address=0)
   reject('unsupported_method_arguments',change=lambda p:_write_span(p,SIGNATURE,b'(I)[B\0'))
  reject('provider_failure',invoke_jni=lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic service failure')))
  reject('provider_exhaustion',invoke_jni=lambda *a:next(iter(())))
 output=dict(component='JNI reference field/no-argument method/release',library_sha256=oracle.LIBRARY_SHA256,
  native_Python_controls=len(rows),rollback_guards=len(guards),cases=rows,negative_cases=guards,native_input_snapshot_used=False,
  private_names_or_payloads_published=False,live_Android_JVM_verified=False,complete_live_lookup_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
 a.output.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS JNI reference members',len(rows),'controls',len(guards),'rollback guards',flush=True)
if __name__=='__main__':main()
