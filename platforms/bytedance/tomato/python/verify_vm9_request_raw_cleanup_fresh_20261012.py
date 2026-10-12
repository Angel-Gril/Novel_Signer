"""Original duplicate configuration insertion with NULL raw value cleanup.

Construct independent guest inputs, then compare direct and actual-wrapper
native execution, ordered allocator effects and all guest/ELF bytes.
"""
from pathlib import Path
import argparse,hashlib,json
import vm9_registry as registry
import verify_vm9_signer_objects as oracle
from verify_vm9_registry import fixture,CONTAINER
from verify_vm9_request_tree_size_fresh_20261012 import PACKED,native_replacement
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000)
PROFILES=('NULL_old','NULL_old_and_new','reload_raw_NULL','binary_key_NULL_old')

class CleanupServices(Services):
    def __init__(self,base,blocks,next_address,key,label):
        super().__init__(blocks);self.effects.next=next_address
        self.base,self.key,self.label=base,key,label
    def mutate(self,pointer,write):
        if pointer==self.key and self.label=='reload_raw_NULL':
            write(CONTAINER+16,(self.base+0x165334).to_bytes(8,'little'))
    def free(self,p,pointer):
        super().free(p,pointer);self.mutate(pointer,lambda a,b:_write_span(p,a,b))
    def native_free(self,c):
        from unicorn.arm64_const import UC_ARM64_REG_X0
        pointer=c.reg_read(UC_ARM64_REG_X0);result=super().native_free(c)
        self.mutate(pointer,lambda a,b:c.mem_write(a,b));return result

def fresh(library,base,label):
    key_bytes=bytes((255,128,1,0,65)) if label=='binary_key_NULL_old' else b'raw_key'
    p,blocks,addresses=fixture(library,base,[key_bytes,key_bytes])
    blocks.pop(addresses[0][2]);prefix=Services(blocks)
    registry.construct_configuration_tree(p,container_address=CONTAINER,
        descriptor_address=oracle.GUEST+0x1300,image_base=base,allocate=prefix.malloc)
    pair=registry.insert_configuration_pair(p,container_address=CONTAINER,
        key_address=addresses[0][0],value_address=0,image_base=base,
        allocate=prefix.malloc,free=prefix.free)
    if label=='reload_raw_NULL':
        _write_span(p,CONTAINER+16,(base+0x182D6C).to_bytes(8,'little'))
    key=addresses[1][0];value=0 if label=='NULL_old_and_new' else addresses[1][2]
    _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x25BF3C,CONTAINER,key,value)))
    return p,key,value,pair,dict(prefix.effects.blocks),prefix.effects.next

def compare(library,base,label,wrapper):
    p,key,value,pair,blocks,next_address=fresh(library,base,label)
    expected=CleanupServices(base,blocks,next_address,key,label)
    actual=CleanupServices(base,blocks,next_address,key,label)
    memory,observed=native_replacement(library,base,p,key,value,wrapper,expected)
    out=registry.insert_configuration_pair(p,container_address=CONTAINER,
        key_address=key,value_address=value,image_base=base,allocate=actual.malloc,free=actual.free)
    assert out==pair and int.from_bytes(_read_span(p,pair+8,8),'little')==value
    assert _read_span(p,oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert expected.events==actual.events and ['free',0] not in actual.events,(label,expected.events,actual.events)
    assert expected.freed==actual.freed and expected.effects.calls==actual.effects.calls
    assert expected.effects.blocks==actual.effects.blocks
    print('PASS',hex(base),'raw NULL cleanup',label,wrapper,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
        all_guest_and_ELF_bytes_match=True,ordered_effects_heap_and_pre_free_bytes_match=True,
        NULL_raw_value_free_skipped=True,cleanup_callback_reloaded=label=='reload_raw_NULL',
        incidental_native_X0_not_claimed=True,native_snapshot_input=False)

def guards(library):
    rows=[]
    for base in BASES:
        for label in ('incoming_key_payload_free_failure','incoming_key_object_free_failure',
                      'unknown_callback_after_key_free'):
            p,key,value,_,blocks,next_address=fresh(library,base,'NULL_old')
            service=CleanupServices(base,blocks,next_address,key,'NULL_old')
            payload=int.from_bytes(_read_span(p,key+16,8),'little')
            before={k:bytes(v) for k,v in p.items()}
            def free(staged,pointer):
                if pointer==(payload if label=='incoming_key_payload_free_failure' else key) and label!='unknown_callback_after_key_free':
                    _write_span(staged,CONTAINER+24,bytes(8))
                    raise RefillUnsupported('injected raw cleanup key release failure')
                service.free(staged,pointer)
                if pointer==key and label=='unknown_callback_after_key_free':
                    _write_span(staged,CONTAINER+16,bytes(8))
            try:
                registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=key,
                    value_address=value,image_base=base,allocate=service.malloc,free=free)
            except RefillUnsupported:pass
            else:raise AssertionError('raw cleanup guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            rows.append(dict(image_base=hex(base),case=label,rejected=True,
                all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS raw cleanup guard',hex(base),label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label in PROFILES:
                for wrapper in (False,True):cases.append(compare(args.library,base,label,wrapper))
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='NULL raw configuration cleanup',cases=cases,
        negative_cases=negative,native_Python_controls=len(cases),rollback_guards=len(negative),
        native_input_snapshot_used=False,whole_request_native_differential_verified=False,
        live_Android_JVM_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'raw cleanup controls,',len(negative),'guards',flush=True)
if __name__=='__main__':main()
