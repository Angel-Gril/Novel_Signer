"""Original JNI integer/reference methods and static fields from fresh ELF.

The signatures and member names here are synthetic controls. Production Java
names remain guest ELF inputs. No real JVM or native memory input is claimed.
The provider consumes the original va_list and compares order and return widths.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_jni_environment as model

G=oracle.GUEST;ENV=G+0x3300;TABLE=G+0x3800;STATUS=G+0x1100;OBJ=G+0x6400
NAME=G+0x6500;SIG=G+0x6600;CLS=G+0x6800;MEMBER=G+0x6900;SP=G+0xEF00
METHOD_SLOTS={b'L':(0x118,8),b'[':(0x118,8),b'Z':(0x130,1),b'B':(0x148,1),
    b'C':(0x160,2),b'S':(0x178,2),b'I':(0x190,4),b'J':(0x1A8,8),b'V':(0x1F0,0)}
FIELD_SLOTS={b'L':(0x488,8),b'[':(0x488,8),b'Z':(0x490,1),b'B':(0x498,1),
    b'C':(0x4A0,2),b'S':(0x4A8,2),b'I':(0x4B0,4),b'J':(0x4B8,8)}
COUNTS={0xD0:2,0x720:1,0x88:1,0x30:2,0xF8:2,0x108:4,0x388:4,0x480:4,0x2F0:4,0x2F8:3,0xB8:2,
    **{s:4 for s,w in METHOD_SLOTS.values()},**{s+0x280:4 for s,w in METHOD_SLOTS.values()},
    **{s:3 for s,w in FIELD_SLOTS.values()}}


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def descriptor(kind):return b'Lfixture/Value;' if kind==b'L' else b'[I' if kind==b'[' else kind


def fresh(lib,base,kind,result_kind,words,profile):
    p=oracle.image_pages(lib,base);p.update(oracle.fresh_pages());w(p,ENV,TABLE)
    for slot in COUNTS:w(p,TABLE+slot,G+0xF600+slot//2)
    _write_span(p,NAME,b'fixtureMember\0');_write_span(p,OBJ,b'fixture/Class\0')
    signature=descriptor(result_kind) if kind in ('static_field','legacy_field') else b'('+b'I'*len(words)+b')'+descriptor(result_kind)
    _write_span(p,SIG,signature+b'\0')
    for i,word in enumerate(words[3:]):w(p,SP+i*8,word)
    return p,signature


class Services:
    def __init__(self,kind,result_kind,words,profile):
        self.kind=kind;self.result_kind=result_kind;self.words=tuple(words);self.profile=profile
        self.events=[];self.exception_checks=0;self.consumed=[]
    def invoke(self,fn,args,read,write):
        slot=(fn-(G+0xF600))*2;assert slot in COUNTS and len(args)==COUNTS[slot] and args[0]==ENV
        p=self.profile;result=0
        if slot==0xD0:result=-1 if p=='push_fail' else 0
        elif slot==0x720:
            self.exception_checks+=1
            wanted={'push_exception':1,'class_exception':2,'final_exception':3}.get(p)
            result=0x101 if self.exception_checks==wanted else 0
        elif slot in (0xF8,0x30):result=0 if p=='NULL_class' else CLS
        elif slot in (0x108,0x388,0x480,0x2F0):result=0 if p=='NULL_member' else MEMBER
        elif slot in (0xB8,0x88):pass
        else:
            result=0xFEDCBA9876543210
            if self.kind in ('static_field','legacy_field'):
                assert args[1:]==((OBJ if self.kind=='legacy_field' else CLS),MEMBER)
            else:
                assert args[1:3]==(CLS if self.kind=='static_method' else OBJ,MEMBER)
                pointer=args[3];raw=read(pointer,32)
                stack,top,vr=[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]
                off=int.from_bytes(raw[24:28],'little',signed=True);values=[]
                for _ in self.words:
                    address=top+off if off<0 else stack
                    values.append(int.from_bytes(read(address,8),'little'))
                    if off<0:off+=8
                    else:stack+=8
                assert tuple(values)==self.words,(values,self.words)
                write(pointer,stack.to_bytes(8,'little')+raw[8:24]+off.to_bytes(4,'little',signed=True)+raw[28:])
                self.consumed.append(dict(pointer=pointer,before=raw.hex(),after=read(pointer,32).hex(),words=values))
        self.events.append([slot,*args,result&model.MASK64]);return result&model.MASK64
    def model(self,p,fn,args):return self.invoke(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self,base):
        imports={}
        for slot,count in COUNTS.items():
            fn=G+0xF600+slot//2
            def call(c,fn=fn,count=count):
                args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(count))
                return self.invoke(fn,args,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            imports[fn-base]=call
        return imports


def call_model(p,kind,words,service,profile):
    kw=dict(entry_stack_address=SP,environment_pointer=0 if profile=='NULL_env' else ENV,
        status_address=0 if profile=='NULL_status' else STATUS,name_address=0 if profile=='NULL_name' else NAME,
        signature_address=SIG,invoke_jni=service.model)
    target=0 if profile=='NULL_target' else OBJ
    if kind=='static_field':return model.read_integer_static_java_field(p,class_name_address=target,**kw)
    if kind=='legacy_field':return model.read_java_reference_field(p,object_reference=target,**kw)
    if kind=='legacy_method':return model.invoke_no_argument_java_reference_method(p,object_reference=target,**kw)
    if kind=='static_method':return model.invoke_integer_argument_static_java_method(p,class_name_address=target,argument_words=words,**kw)
    return model.invoke_integer_argument_java_method(p,object_reference=target,argument_words=words,**kw)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    words=(7,11,0x1020304050607080,19);profiles=[]
    for kind in ('method','static_method'):
        profiles.extend((kind,k,words,'return_'+k.decode()) for k in METHOD_SLOTS)
        profiles.extend((kind,b'I',tuple(range(1,n+1)),'arity_'+str(n)) for n in (0,1,2,3,5,7))
    profiles.extend(('static_field',k,(),'return_'+k.decode()) for k in FIELD_SLOTS)
    profiles.extend((kind,b'L',(),'legacy') for kind in ('legacy_field','legacy_method'))
    for kind in ('method','static_method','static_field'):
        profiles.extend((kind,b'I',() if kind=='static_field' else words,label) for label in
            ('NULL_env','NULL_status','NULL_target','NULL_name','push_fail','push_exception','NULL_class','class_exception','NULL_member','final_exception'))
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for kind,return_kind,arguments,label in profiles:
            p,signature=fresh(args.library,base,kind,return_kind,arguments,label)
            expected=Services(kind,return_kind,arguments,label);actual=Services(kind,return_kind,arguments,label)
            entry=0x2715B8 if kind=='static_field' else 0x26FA00 if kind=='legacy_field' else 0x26F2A4 if kind=='static_method' else 0x26F650
            registers={getattr(arm,'UC_ARM64_REG_X'+str(i+5)):word for i,word in enumerate(arguments[:3])}
            observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            temp=SP-(0x60 if kind in ('static_field','legacy_field') else 0x1A8);observed[temp,8]=None
            if kind not in ('static_field','legacy_field'):
                for address in (SP-0x48,SP-0x70):observed[address,32]=None
                if arguments:observed[SP-0x88,min(3,len(arguments))*8]=None
                if len(arguments)>3:observed[SP,(len(arguments)-3)*8]=None
            if label not in ('NULL_env','NULL_name','NULL_class','class_exception','NULL_member','push_fail','push_exception') and kind not in ('static_field','legacy_field'):
                if label!='NULL_target' or kind=='static_method':observed[SP-0x1A0,32]=None
            returned,memory,_,_=oracle.native(args.library,base,entry,
                [0 if label=='NULL_env' else ENV,0 if label=='NULL_status' else STATUS,0 if label=='NULL_target' else OBJ,
                 0 if label=='NULL_name' else NAME,SIG],p,extra_registers=registers,host_imports=expected.imports(base),
                observed_memory=observed,instruction_limit=15000)
            result=call_model(p,kind,arguments,actual,label);word=result.reference if kind.startswith('legacy') else result.word
            assert returned==word,(hex(base),kind,label,'return',hex(returned),hex(word))
            assert _read_span(p,G,0xA000)==memory,(kind,label,'payload')
            for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(kind,label,'scratch/image',hex(a),n)
            assert actual.events==expected.events and actual.consumed==expected.consumed,(kind,label,'JNI order/arguments')
            cases.append(dict(image_base=hex(base),kind=kind,case=label,return_kind=return_kind.decode(),argument_count=len(arguments),
                original_returned=True,all_guest_payload_and_image_pages_match=True,logical_scratch_matches=True,
                ordered_JNI_services_match=True,consumed_integer_arguments_match=True,return_width_and_status_match=True,
                native_snapshot_input=False))
            print('PASS',hex(base),kind,label,flush=True)
    base=0x122C0000
    for label in ('unaligned_stack','missing_provider','argument_count','negative_word','oversized_word','FP_parameter','FP_return','malformed_signature','trailing_signature','unmapped_stack','provider_failure'):
        p,_=fresh(args.library,base,'method',b'I',words,label);service=Services('method',b'I',words,label)
        kw=dict(entry_stack_address=SP,environment_pointer=ENV,status_address=STATUS,object_reference=OBJ,
            name_address=NAME,signature_address=SIG,argument_words=words,invoke_jni=service.model)
        if label=='unaligned_stack':kw['entry_stack_address']=SP-1
        elif label=='missing_provider':kw['invoke_jni']=None
        elif label=='argument_count':kw['argument_words']=words[:-1]
        elif label=='negative_word':kw['argument_words']=(-1,*words[1:])
        elif label=='oversized_word':kw['argument_words']=(1<<64,*words[1:])
        elif label=='FP_parameter':_write_span(p,SIG,b'('+b'F'+b')I\0')
        elif label=='FP_return':_write_span(p,SIG,b'('+b')D\0')
        elif label=='malformed_signature':_write_span(p,SIG,b'('+b'I\0')
        elif label=='trailing_signature':_write_span(p,SIG,b'('+b')II\0')
        elif label=='unmapped_stack':kw['entry_stack_address']=0x66001000
        else:kw['invoke_jni']=lambda *a:next(iter(()))
        before={k:bytes(v) for k,v in p.items()}
        try:model.invoke_integer_argument_java_method(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Integer/reference/void JNI methods and non-FP static fields',library_sha256=oracle.LIBRARY_SHA256,
        native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,
        integer_GP_and_stack_arguments_verified=True,legacy_reference_subset_regression_verified=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,synthetic_control_names_and_signatures=True,
        physical_register_spills_verified=False,FP_arguments_or_returns_verified=False,cold_live_initializer_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS integer JNI members',len(cases),'controls',len(guards),'guards',flush=True)
if __name__=='__main__':main()
