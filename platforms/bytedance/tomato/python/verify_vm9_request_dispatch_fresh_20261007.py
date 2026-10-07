"""Locate the first post-+0x1684f0 native dispatch instruction."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X8, UC_ARM64_REG_X9
import verify_vm9_signer_objects as oracle

class DispatchStop(Exception):
    def __init__(self, offset, regs): self.offset, self.regs = offset, regs

def case(library, image, object_offset, preserved_x8):
    pages=oracle.image_pages(library,image); pages.update(oracle.fresh_pages())
    state={'prelude':False}
    def observe(cpu,address):
        off=address-image
        if off==0x1684F0: state['prelude']=True; return
        if state['prelude'] and not (0x168324 <= off <= 0x1684F0):
            regs={name:hex(cpu.reg_read(reg)) for name,reg in (
                ('pc',UC_ARM64_REG_PC),('sp',UC_ARM64_REG_SP),('x0',UC_ARM64_REG_X0),
                ('x1',UC_ARM64_REG_X1),('x2',UC_ARM64_REG_X2),('x3',UC_ARM64_REG_X3),
                ('x4',UC_ARM64_REG_X4),('x8',UC_ARM64_REG_X8),('x9',UC_ARM64_REG_X9))}
            raise DispatchStop(off,regs)
    try:
        oracle.native(library,image,0x256ED4,[oracle.GUEST+object_offset,0,0,0,0],pages,
            extra_registers={UC_ARM64_REG_X8:preserved_x8},instruction_observer=observe,
            instruction_limit=100000)
    except DispatchStop as stop:
        return dict(image_base=hex(image),object_offset=hex(object_offset),
            preserved_x8=hex(preserved_x8),first_post_prelude_offset=hex(stop.offset),
            registers=stop.regs,native_input_snapshot_used=False)
    raise AssertionError('dispatch did not leave generic prelude')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,default=Path(r'C:\AI\6\libmetasec_ml_71332.so'));ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
      for off,x8 in ((0x1800,0x7004EDD8),(0x1FF8,0x64000000),(0x2800,image+0x257050)):
        rows.append(case(a.library,image,off,x8));print('dispatch',hex(image),hex(off),'PASS',flush=True)
    report=dict(schema='vm9-request-dispatch-fresh-observation-v1',evidence_date='2026-10-07',sample_sha256=oracle.LIBRARY_SHA256,controls=len(rows),cases=rows,complete_python_medusa=False,fresh_input_signer_output_verified=False,current_online_header_matrix_verified=False,limitations=['This locates the first native handler after +0x1684f0; it does not implement the handler or nested VM.','Fresh synthetic object/x8 inputs only; no URL/header/JNI conversion, JVM, server request or signature output.'])
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print('dispatch',len(rows),'fresh observations PASS')
if __name__=='__main__':main()
