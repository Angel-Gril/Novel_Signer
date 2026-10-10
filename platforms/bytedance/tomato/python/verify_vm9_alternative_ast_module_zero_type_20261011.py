"""Actual B zero-count type caller saves with explicit incoming X22.

Native snapshots are comparisons only; allocation is an explicit pure plan.
"""
from __future__ import annotations
import argparse,hashlib,itertools,json
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_alternative_ast_module_segments_custom_20261011 as previous
from vm9_allocator import RefillUnsupported,_read_span,_write_span

layout=previous.layout;alternative=previous.alternative;BASES=previous.BASES
MASK=(1<<64)-1

def spec(label,kinds=(1,),*,x22=0,length=1,leading=b'',following=b'',**kw):
    entries=[previous.previous.imported(k,length,i) for i,k in enumerate(kinds)]
    counts={k:0 for k in kinds};exports=[]
    for i,k in enumerate(kinds):
        exports.append((bytes([97+i])*min(length,24),k,counts[k]));counts[k]+=1
    case=previous.previous.spec(label,exports,definitions=[],imports=entries,
        large_arena=True,entry_x22=x22,entry_x28=0x123456789ABCDEF0,expected_status=0,**kw)
    case['blob']=case['blob'][:8]+leading+previous.previous.section(1,b'\0')+following+case['blob'][8:]
    return case

def fixtures():
    rows=[]
    for kind in (1,2,3):
        for x22 in (0,0xFEDCBA9876543210,MASK):
            rows.append(spec(f'zero_type_{kind}_{x22:x}',(kind,),x22=x22))
        for n in (0,1,21,22,23,31):
            for pad in (0,0x39,0xFF):
                rows.append(spec(f'names_{kind}_{n}_{pad}',(kind,),x22=0x8060402012345678,
                    length=n,frame_padding=pad))
    for order in itertools.permutations((1,2,3)):
        rows.append(spec('order_'+''.join(map(str,order)),order*2,x22=MASK,length=0))
    for name,data in ((b'dylink',b'\0'*5),(b'dylink.0',b''),(b'linking',b'\2'),
            (b'target_features',b'\0'),(b'reloc.CODE',b'\0\0')):
        blob=previous.custom.custom(name,data)
        for early in (True,False):
            rows.append(spec('custom_'+name.decode().replace('.','_')+'_'+str(early),(1,2,3),
                x22=MASK,custom=True,leading=blob if early else b'',following=b'' if early else blob))
    for kind in (1,2,3):
        for label,settings in [('table',dict(tables=[(0x70,1,3,9)])),
                ('memory',dict(memories=[(1,3,9)])),
                ('global',dict(globals_=[previous.previous.previous.previous.entry(ops=[(2,7)])]))]:
            rows.append(spec('definition_'+str(kind)+'_'+label,(kind,),x22=MASK,**settings))
    rows.append(spec('no_inline_exports',(1,2,3),x22=MASK,length=23,model_settings=dict(enable_inline_exports=False)))
    rows.append(spec('generic_custom',(3,),x22=MASK,leading=previous.previous.section(0,b'\1x')))
    return rows

def native(args,base,case):
    saved=previous.heap.oracle.native;saves=[]
    def instrumented(*a,**kw):
        observe=kw['instruction_observer']
        def observed(cpu,address):
            if address==base+0x31B360:cpu.reg_write(arm.UC_ARM64_REG_X22,case.get('entry_x22',0))
            if address==base+0x31E768:
                sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
                assert sp+0x10==layout.STATE-0x100
                value=int.from_bytes(cpu.mem_read(sp+0x10,8),'little')
                state=int.from_bytes(cpu.mem_read(sp+0x28,8),'little')
                assert (value,state)==(case['entry_x22'],layout.STATE),(case['label'],hex(value),hex(state))
                saves.append((value,state))
            observe(cpu,address)
        kw['instruction_observer']=observed;return saved(*a,**kw)
    try:
        previous.heap.oracle.native=instrumented
        result=_native(args,base,case)
    finally:previous.heap.oracle.native=saved
    assert len(saves)==1,case['label']
    return result

_native=previous.native;_options=previous.options

def compare(args,base,case):
    saved=previous.native,previous.options
    try:
        previous.native=native
        previous.options=lambda c:_options(c)|dict(entry_x22=c.get('entry_x22'))
        with previous.arena(case):row=previous.compare(args,base,case)
    finally:previous.native,previous.options=saved
    row.update(explicit_entry_x22_hex=hex(case['entry_x22']),actual_type_reserve_caller_saves_verified=True)
    return row

def negatives(args):
    rows=[];base=BASES[0];case=spec('guard',(3,),x22=MASK)
    def reject(label,changes=None,fault=None):
        with previous.arena(case):
            p=previous.previous.previous.previous.prepare(args,base,case);offset=0
            def allocate(size):
                nonlocal offset
                out=layout.HEAP+offset;offset+=(size+15)&~15;return out
            params=dict(image_base=base,input_address=layout.DATA,input_size=len(case['blob']),output_address=layout.OUT,
                entry_stack_address=layout.ENTRY,varuint_scratch_address=layout.SCRATCH,allocate=allocate,
                **(previous.previous.options(case)|_options(case)|dict(entry_x22=case['entry_x22'])))
            params.update(changes or {});before={k:bytes(v) for k,v in p.items()};write=alternative._write_span;hits=[]
            def injected(current,address,data):
                if fault(address,data):hits.append(address);raise RefillUnsupported('injected zero-type caller save failure')
                return write(current,address,data)
            try:
                if fault:alternative._write_span=injected
                try:alternative.run_reader_ast_module(p,**params)
                except (RefillUnsupported,ValueError):pass
                else:raise AssertionError('guard accepted: '+label)
            finally:alternative._write_span=write
            assert before=={k:bytes(v) for k,v in p.items()},label
            if fault:assert hits,label
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
    for label,value in [('missing',None),('bool',True),('negative',-1),('overflow',1<<64),('string','0')]:
        reject('entry_x22_'+label,dict(entry_x22=value))
    reject('imports_closed',dict(enable_table_memory_global_imports=False,enable_inline_table_memory_global_imports=False))
    reject('inline_imports_closed',dict(enable_inline_table_memory_global_imports=False))
    reject('X22_store_failure',fault=lambda a,d:a==layout.STATE-0x100 and len(d)==8)
    reject('X19_store_failure',fault=lambda a,d:a==layout.STATE-0xE8 and len(d)==8)
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','libc','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==previous.heap.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==previous.heap.LIBC_HASH
    cases=fixtures();guards=negatives(args);rows=[]
    moved=[next(c for c in cases if c['label']==f'zero_type_{kind}_{MASK:x}') for kind in (1,2,3)]
    for base in BASES:
        for i,case in enumerate(cases,1):
            rows.append(compare(args,base,case))
            if i%16==0:print('B zero type',hex(base),i,'/',len(cases),'passed',flush=True)
        for delta in (-0xC80,0x100):
            with layout.layout(delta):
                for c in moved:rows.append(compare(args,base,{**c,'label':c['label']+'_SP_'+str(delta)}))
        with previous.previous.previous.previous.definitions.guest_layout(0x7000000000):
            for c in moved:rows.append(compare(args,base,{**c,'label':c['label']+'_high_guest'}))
    evidence=dict(schema='vm9-alternative-ast-module-zero-type-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=previous.heap.oracle.LIBRARY_SHA256,matching_libc_sha256=previous.heap.LIBC_HASH,
        native_Python_zero_type_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=18,
        explicit_entry_x22_required_for_zero_type_imports=True,entry_x22_default=None,
        relocated_entry_stack_controls=12,relocated_full_guest_controls=6,
        native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
        independent_Python_factory_implemented=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B zero type:',len(rows),'native/Python,',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
