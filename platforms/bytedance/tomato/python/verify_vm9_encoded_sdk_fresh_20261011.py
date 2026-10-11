"""Original encoded/plain SDK getters with a shared property conversion owner.

Fresh ELF inputs and explicit property services; singleton136 is initialized.
All image pages and the original property buffer are compared after execution.
Native memory never supplies Python input and decoded property names stay local.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_configuration_init as model

G=oracle.GUEST;TP=G+0x3000;WRAPPER=G+0x3500;OBJECT=G+0x3600;PROPERTY=G+0x3700;SP=G+0xEF00


def delta(base):
    pc=base+0x1CFAF8
    return (((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF4067864)&model.MASK64


def fresh(lib,base,kind,cache=0):
    p=oracle.image_pages(lib,base);p.update(oracle.fresh_pages())
    model._w(p,TP+8,G+0x3100);model._w(p,G+0x3110,137,4)
    model._w(p,base+0x3D1680,0x101);model._w(p,base+0x3D1678,WRAPPER);model._w(p,WRAPPER,OBJECT)
    _write_span(p,OBJECT,bytes(0x88))
    address=(model._u(p,base+0x37B260)+delta(base))&model.MASK64 if kind=='encoded' else base+0x3DF148
    model._w(p,address,cache,4);return p,address


class Services:
    def __init__(self,raw,status=0):self.raw=raw;self.status=status;self.events=[]
    def find(self,p,name):
        result=0 if self.raw is None else PROPERTY;self.events.append(['find',name,result]);return result
    def read(self,p,prop,buffer):
        assert prop==PROPERTY
        _write_span(p,buffer,self.raw+b'\0');self.events.append(['read',prop,buffer,self.status]);return self.status
    def combined(self,p,name,buffer):
        prop=self.find(p,name)
        if prop:self.read(p,prop,buffer)
        return self.raw
    def imports(self):
        def reg(c,i):return c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
        def find(c):
            result=0 if self.raw is None else PROPERTY;self.events.append(['find',reg(c,0),result]);return result
        def read(c):
            assert (reg(c,0),reg(c,1))==(PROPERTY,0)
            c.mem_write(reg(c,2),self.raw+b'\0');self.events.append(['read',PROPERTY,reg(c,2),self.status]);return self.status&model.MASK64
        return {0x348250:find,0x348260:read}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    profiles=[('cached',27,None,0,27),('cached_signed',0xFFFFFFFF,None,0,-1),('absent',0,None,0,0),
              ('empty',0,b'',0,0),('SDK27',0,b'27',2,27),('SDK30',0,b'30',2,30),
              ('whitespace_suffix',0,b' \t+27tail',9,27),('zero',0,b'0',1,0),('negative',0,b'-27',3,0),
              ('invalid',0,b'invalid',7,0),('signed_maximum',0,b'2147483647',10,2147483647),
              ('signed_minimum',0,b'-2147483648',11,0),('read_status_ignored',0,b'30',-7,30)]
    cases=[];guards=[]
    for base in (0x122C0000,0x775C205000):
        for kind in ('encoded','plain'):
            for label,cache,raw,status,value in profiles:
                p,cache_address=fresh(args.library,base,kind,cache);expected=Services(raw,status);actual=Services(raw,status)
                entry=0x1CFAF8 if kind=='encoded' else 0x271BA8;buffer=SP-(0x160 if kind=='encoded' else 0xA0);size=256 if kind=='encoded' else 92
                observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000};observed[buffer,size]=None
                returned,memory,_,_=oracle.native(args.library,base,entry,[],p,libc=args.libc,
                    real_singletons=True,real_diagnostics=True,real_mutexes=True,real_recursive_mutexes=True,
                    extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
                    host_imports=expected.imports(),instruction_limit=100000,observed_memory=observed)
                if kind=='encoded':got=model.get_encoded_sdk(p,image_base=base,entry_stack_address=SP,find_property=actual.find,read_property=actual.read)
                else:got=model.get_cached_sdk(p,image_base=base,buffer_address=buffer,read_property=lambda p,name:actual.combined(p,name,buffer))
                assert got==value and (returned&0xFFFFFFFF)==(got&0xFFFFFFFF),(kind,label,'return')
                own=_read_span(p,G,0xA000)
                if own!=memory:
                    offset=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((kind,label,'guest',hex(offset)))
                for (a,n),data in observed.items():assert _read_span(p,a,n)==data,(hex(base),kind,label,hex(a))
                assert actual.events==expected.events,(kind,label,'property order')
                assert model._u(p,cache_address,4)==(cache if cache else max(0,value))
                cases.append(dict(image_base=hex(base),kind=kind,case=label,original_returned=True,returned_SDK=got,
                    all_guest_payload_and_image_pages_match=True,property_buffer_match=True,ordered_property_services_match=True,
                    cache_word_match=True,native_snapshot_input=False))
                print('PASS',hex(base),kind,label,flush=True)
    base=0x122C0000
    for label in ('unaligned_stack','missing_find','missing_read','bad_property_pointer','cold_singleton136',
                  'active_instrumentation','decimal_overflow','unterminated_buffer','provider_exhaustion'):
        p,_=fresh(args.library,base,'encoded');service=Services(b'30');kw=dict(find_property=service.find,read_property=service.read,entry_stack_address=SP)
        if label=='unaligned_stack':kw['entry_stack_address']=SP-1
        elif label=='missing_find':kw['find_property']=None
        elif label=='missing_read':kw['read_property']=None
        elif label=='bad_property_pointer':kw['find_property']=lambda *a:-1
        elif label=='cold_singleton136':model._w(p,base+0x3D1680,0)
        elif label=='active_instrumentation':model._w(p,OBJECT+0x10,1);model._w(p,OBJECT+0x18,2)
        elif label=='decimal_overflow':service.raw=b'2147483648'
        elif label=='unterminated_buffer':kw['read_property']=lambda p,prop,buffer:_write_span(p,buffer,b'X'*256)
        else:kw['find_property']=lambda *a:next(iter(()))
        before={k:bytes(v) for k,v in p.items()}
        try:model.get_encoded_sdk(p,image_base=base,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError,StopIteration):pass
        else:raise AssertionError(label+' accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    result=dict(component='Encoded SDK getter and shared decimal conversion',library_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=LIBC_SHA256,
        native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,
        encoded_cold_property_path_verified=True,initialized_singleton136_required=True,plain_getter_regression_verified=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,cold_singleton136_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS encoded/plain SDK',len(cases),'controls',len(guards),'guards',flush=True)


if __name__=='__main__':main()
