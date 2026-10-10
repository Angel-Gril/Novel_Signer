"""Fresh native instruction-format conversion; sample contents stay local."""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000)

def fixture(count,seed=0,*,equal=False,rotation=None,odd=False):
    rng=random.Random(0xB778+seed+count)
    triples=[]
    for i in range(count):
        width=rng.randrange(1,33) if not odd else rng.randrange(256)
        shift=rng.randrange(33-width) if not odd else rng.randrange(256)
        triples.append((i%256,shift,width))
    target=[(i%256,rng.randrange(33-n) if not odd else rng.randrange(256),n) for i,(_,_,n) in enumerate(triples)]
    if equal:target=triples[:]
    rot=rng.randrange(256) if rotation is None else rotation
    return dict(label=f'fields_{count}_seed_{seed}_equal_{equal}_rot_{rot}_odd_{odd}',
        source=(82,rot,77,triples),target=(82 if equal else 73,rot if equal else 0,19,target),
        word=rng.getrandbits(32),equal=equal,odd=odd)

def fixtures():
    rows=[]
    for count in (0,1,2,6,7,8,9,15,16,17,23,24,31,32,33,64):
        for seed in range(3):rows.append(fixture(count,seed,odd=seed==2))
        rows.append(fixture(count,7,equal=True,odd=True))
    for rotation in (0,1,31,32,33,127,128,129,224,255):
        rows.append(fixture(9,11,rotation=rotation))
    for count in (0,1,8,16,17):
        for word in (0,1,0x80000000,0xFFFFFFFF):
            row=fixture(count,19);row['word']=word;row['label']+=f'_word_{word:x}';rows.append(row)
    for count in (1,7,8,16,17):
        row=fixture(count,53);tag,rot,key,fields=row['source']
        row['source']=(tag,rot,key,[(count-1-i,s,n) for i,(_,s,n) in enumerate(fields)])
        row['label']+='_reverse_indices';rows.append(row)
    for source_count,target_count in ((0,2),(1,2),(2,1),(8,1),(17,2)):
        row=fixture(source_count,61);tag,rot,key,fields=row['source']
        row['source']=(tag,rot,key,[(i%target_count,s,n) for i,(_,s,n) in enumerate(fields)])
        row['target']=fixture(target_count,62)['target'];row['label']+=f'_target_count_{target_count}';rows.append(row)
    return rows

def actual_fixtures(library):
    image=oracle.image_pages(library,0);p=oracle.fresh_pages();frame=oracle.GUEST+0x4000
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);cs.detail=True;value=None;writes=[]
    for i in cs.disasm(_read_span(image,0x29F110,0x180),0x29F110):
        if i.mnemonic=='mov':
            assert i.op_str.startswith('w8, #') and i.operands[1].type==ARM64_OP_IMM
            value=i.operands[1].imm&0xFFFFFFFF
        elif i.mnemonic=='add':
            assert i.op_str.startswith('x8, sp, #') and i.operands[2].type==ARM64_OP_IMM
            value=frame+i.operands[2].imm
        else:
            assert i.mnemonic in ('str','strb') and cs.reg_name(i.operands[1].mem.base)=='sp' and not i.writeback
            register=cs.reg_name(i.operands[0].reg);assert register in ('w8','x8','wzr')
            width=1 if i.mnemonic=='strb' else 8 if register=='x8' else 4
            address=frame+i.operands[1].mem.disp;v=0 if register=='wzr' else value
            assert v is not None and frame+0x18<=address<frame+0x90
            _write_span(p,address,v.to_bytes(width,'little'));writes.append(i.address)
    assert i.address==0x29F28C and len(writes)==51
    def instruction(address,mnemonic,operands=None):
        i=next(cs.disasm(_read_span(image,address,4),address))
        assert i.mnemonic==mnemonic and (operands is None or i.op_str==operands)
        return i
    def immediate(address):
        i=instruction(address,'mov');assert i.operands[1].type==ARM64_OP_IMM
        return i.operands[1].imm
    instruction(0x2AB594,'ldr','q0, [x8, #0x4b0]')
    instruction(0x2AB5C8,'ldr','d0, [x8, #0x1b0]')
    high=instruction(0x2AB5D0,'movk','w8, #0x1010, lsl #16').operands[1].imm
    raw=[_read_span(image,0x6E4B0,16)+immediate(0x2AB598).to_bytes(2,'little'),
        _read_span(image,0x6E1B0,8)+(immediate(0x2AB5CC)|(high<<16)).to_bytes(4,'little'),
        immediate(0x2AB5FC).to_bytes(4,'little')+immediate(0x2AB600).to_bytes(2,'little')]
    tags=[immediate(a) for a in (0x2AB628,0x2AB644,0x2AB65C)]
    rows=[]
    for index in range(3):
        address=frame+0x48+index*24;header=tuple(_read_span(p,address,3))
        ptr=int.from_bytes(_read_span(p,address+8,8),'little');count=int.from_bytes(_read_span(p,address+16,4),'little')
        fields=_read_span(p,ptr,count*3);source=(*header,[tuple(fields[n:n+3]) for n in range(0,len(fields),3)])
        target=(tags[index],0,0,[tuple(raw[index][n:n+3]) for n in range(0,len(raw[index]),3)])
        assert count==len(target[3])
        for bit in range(-1,32):
            rows.append(dict(label=f'actual_constructor_row_{index}_basis_{bit}',source=source,target=target,
                word=0 if bit<0 else 1<<bit,equal=False,odd=False,actual_ELF=True))
    return rows

def prepare(case,guest=None):
    guest=oracle.GUEST if guest is None else guest
    p=oracle.fresh_pages();context=guest+0x1000;source=guest+0x1020;target=guest+0x1040
    for record,triple,spec in ((source,guest+0x2000,case['source']),(target,guest+0x3000,case['target'])):
        tag,rot,key,fields=spec
        _write_span(p,record,bytes([tag,rot,key])+b'\x6d'*5+triple.to_bytes(8,'little')+
            len(fields).to_bytes(4,'little')+b'\xcc'*4)
        # The native count loads are uint32, even though records are 24 bytes.
        _write_span(p,triple,bytes(v for row in fields for v in row))
    _write_span(p,context,target.to_bytes(8,'little'))
    return p,context,source,target

def native(args,base,case,*,sp_delta=0):
    p,context,source,target=prepare(case);captured=[];saved=oracle.Uc
    def factory(*a,**kw):
        cpu=saved(*a,**kw);captured.append(cpu);return cpu
    try:
        oracle.Uc=factory
        result,memory,calls,ledger=oracle.native(args.library,base,0x2DB778,
            [context,source,case['word']],p,
            extra_registers={arm.UC_ARM64_REG_SP:oracle.GUEST+0xEF00+sp_delta},
            instruction_limit=100000,code_hook_ranges=((base+0x2DB778,base+0x2DBE20),))
    finally:oracle.Uc=saved
    assert not calls and not ledger
    cpu=captured[0]
    assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP
    assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00+sp_delta
    assert memory==_read_span(p,oracle.GUEST,0xA000)
    return result,p,source,target

def compare(args,base,case,**kw):
    want,p,source,target=native(args,base,case,**kw);before={k:bytes(v) for k,v in p.items()}
    got=alternative.convert_parser_instruction_word(p,source_codec_address=source,
        target_codec_address=target,word=case['word'])
    assert got==want,(case['label'],hex(got),hex(want))
    assert before=={k:bytes(v) for k,v in p.items()}
    return dict(label=case['label'],image_base_hex=hex(base),guest_hex=hex(oracle.GUEST),
        source_field_count=len(case['source'][3]),expected_identity=case['equal'],
        arbitrary_byte_fields=case['odd'],SP_delta=kw.get('sp_delta',0),
        native_Python_return_match=True,natural_return_SP_and_guest_verified=True,
        all_Python_pages_unchanged=True,native_input_snapshot_used=False,actual_ELF_codecs=case.get('actual_ELF',False))

def negatives():
    rows=[]
    for label,changes in [('word_bool',dict(word=True)),('word_negative',dict(word=-1)),
            ('word_overflow',dict(word=1<<32)),('source_null',dict(source_codec_address=0)),
            ('source_unmapped',dict(source_codec_address=0x78000000)),
            ('target_overflow',dict(target_codec_address=(1<<64)-8)),
            ('target_bool',dict(target_codec_address=True)),('bound_bool',dict(max_fields=True)),
            ('bound_negative',dict(max_fields=-1)),('field_budget',dict(max_fields=7))]:
        p,_,source,target=prepare(fixture(8));before={k:bytes(v) for k,v in p.items()}
        kw=dict(source_codec_address=source,target_codec_address=target,word=7);kw.update(changes)
        try:alternative.convert_parser_instruction_word(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[];cases=fixtures()+actual_fixtures(args.library)
    for base in BASES:
        for case in cases:rows.append(compare(args,base,case))
        for delta in (-0x1000,0x100):
            for n in (7,8,16,17):rows.append(compare(args,base,fixture(n,31,odd=True),sp_delta=delta))
        print('B parse codec',hex(base),len(rows),'passed',flush=True)
    saved=oracle.GUEST,oracle.STOP
    try:
        oracle.GUEST=0x7000000000;oracle.STOP=oracle.GUEST+0xF000
        for base in BASES:
            for n in (0,6,7,8,16,17):rows.append(compare(args,base,fixture(n,73,odd=True)))
    finally:oracle.GUEST,oracle.STOP=saved
    guards=negatives()
    evidence=dict(schema='vm9-alternative-parse-codec-fresh-v1',evidence_date='2026-10-11',
        evidence_timezone='Asia/Shanghai',sample_sha256=oracle.LIBRARY_SHA256,
        native_Python_codec_controls=len(rows),rollback_negative_controls=len(guards),
        pre_change_behavior_RED_controls=12,actual_ELF_codec_controls=sum(r['actual_ELF_codecs'] for r in rows),
        relocated_entry_stack_controls=16,relocated_full_guest_controls=12,
        native_input_snapshot_used=False,private_payloads_published=False,
        independent_Python_factory_implemented=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B codec',len(rows),'native/Python',len(guards),'guards',flush=True)

if __name__=='__main__':main()
