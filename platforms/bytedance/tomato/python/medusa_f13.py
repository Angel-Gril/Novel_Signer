# -*- coding: utf-8 -*-
# medusa_f13.py — X-Medusa field13 core (16 bytes) pure-Python calculator.
# chain: query string -> SM3 -> BIG VM (12ae2000, pure ARM64 interpretation) -> key32
#        -> f13[0:16] = key32[0:16] XOR key32[16:32]
# No unicorn / unidbg / Android runtime. Deps: capstone + snapshot blobs in udghook/
# (dump_bigstart_m0/m1/m2/copy2.bin + dump_bigstart_regs.txt — one-time dump, frozen ts/rand).
# Verified: r0 key32 exact (48b9ab07..e1), r2/r3 f13-core exact via query swap.
import struct, hashlib, sys, time
WALLTS = [1790085004]  # frozen harness wall clock; override for live
from capstone import *
from capstone.arm64_const import *

import os
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'udghook') + os.sep
M0A, M1A, C2A, M2A = 0x12290000, 0x12800000, 0x11EC0000, 0xe4fc0000
DIGEST_ADDR = 0x122ac240      # SM3(query) input slot (32 bytes)
KEY32_ADDR  = 0xe4ff2478      # BIG output key32
H711 = 0x1257f810             # BIG VM entry handler (first dispatch target)
H189 = 0x1256ee8c             # return handler — stop PC
TPIDR = 0xe4fff718
MASK64 = (1<<64)-1

SNAP0 = open(D+'dump_bigstart_m0.bin','rb').read()
SNAP1 = open(D+'dump_bigstart_m1.bin','rb').read()
SNAP2 = open(D+'dump_bigstart_m2.bin','rb').read()
SNAP3 = open(D+'dump_bigstart_copy2.bin','rb').read()
INIT_REGS = dict((t.split('=')[0], int(t.split('=')[1],16))
                 for t in open(D+'dump_bigstart_regs.txt').read().split())

class Mem:
    PS = 0x1000
    def __init__(self):
        self.pages = {}
    def _pg(self, a):
        k = a & ~(self.PS-1)
        p = self.pages.get(k)
        if p is None:
            p = bytearray(self.PS); self.pages[k] = p
        return p
    def load(self, a, data):
        off = 0
        while off < len(data):
            aa = a + off
            k = aa & ~(self.PS-1); o = aa - k
            n = min(self.PS - o, len(data) - off)
            p = self.pages.get(k)
            if p is None:
                p = bytearray(self.PS); self.pages[k] = p
            p[o:o+n] = data[off:off+n]
            off += n
    def read(self, a, n):
        out = bytearray()
        while n > 0:
            k = a & ~(self.PS-1); o = a - k
            c = min(self.PS - o, n)
            p = self.pages.get(k)
            out += p[o:o+c] if p is not None else bytes(c)
            a += c; n -= c
        return bytes(out)
    def write(self, a, data):
        n = len(data); off = 0
        while off < n:
            aa = a + off
            k = aa & ~(self.PS-1); o = aa - k
            c = min(self.PS - o, n - off)
            p = self._pg(k)
            p[o:o+c] = data[off:off+c]
            off += c

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
dcache = {}
def decode(a):
    i = dcache.get(a)
    if i is None:
        b = mem.read(a,4)
        i = next(md.disasm(b,a))
        dcache[a] = i
    return i

# ---------------- cpu state (reset per compute) ----------------
REG = [0]*31
SP = [0]
PC = [0]
N=[0]; Z=[0]; C=[0]; V=[0]

def regidx(rname):
    if rname in ('sp','wsp'): return 'sp'
    if rname=='fp': return 29
    if rname=='lr': return 30
    if rname in ('xzr','wzr'): return 'zr'
    return int(rname[1:])

def get_reg(rname):
    t = regidx(rname)
    if t=='zr': return 0
    v = SP[0] if t=='sp' else REG[t]
    if rname[0]=='w': v &= 0xFFFFFFFF
    return v

def set_reg(rname, val):
    val &= MASK64
    t = regidx(rname)
    if t=='zr': return
    if rname[0]=='w': val &= 0xFFFFFFFF
    if t=='sp': SP[0]=val
    else: REG[t]=val

EXT = {ARM64_EXT_UXTB:8, ARM64_EXT_UXTH:16, ARM64_EXT_UXTW:32, ARM64_EXT_UXTX:64,
       ARM64_EXT_SXTB:-8, ARM64_EXT_SXTH:-16, ARM64_EXT_SXTW:-32, ARM64_EXT_SXTX:-64}
def apply_ext(v, ext):
    if ext==0: return v
    bits = EXT[ext]
    if bits>0: return v & ((1<<bits)-1)
    b=-bits; m=(1<<b)-1; v&=m
    return v | (~m & MASK64) if (v>>(b-1))&1 else v

def apply_shift(v, st, sv, is64):
    if st==0 or sv==0: return v
    if st==ARM64_SFT_LSL: return (v<<sv)&MASK64
    if st==ARM64_SFT_LSR: return (v & (MASK64 if is64 else 0xFFFFFFFF))>>sv
    if st==ARM64_SFT_ASR:
        w = 64 if is64 else 32; v &= (1<<w)-1
        if (v>>(w-1))&1: v |= MASK64 ^ ((1<<w)-1)
        return (v>>sv)&MASK64
    if st==ARM64_SFT_ROR:
        w = 64 if is64 else 32; v &= (1<<w)-1
        return ((v>>sv)|(v<<(w-sv))) & ((1<<w)-1)
    return v

def rval(op, is64=True):
    if op.type==ARM64_OP_IMM: return op.imm & MASK64
    if op.type==ARM64_OP_REG:
        rn = md.reg_name(op.reg)
        v = get_reg(rn)
        v = apply_ext(v, op.ext)
        is64 = not rn.startswith('w')   # shift width follows operand register width
        v = apply_shift(v, op.shift.type, op.shift.value, is64)
        return v
    raise Exception('bad rval op')

def maddr(op):
    base = get_reg(md.reg_name(op.mem.base)) if op.mem.base else 0
    if op.mem.index:
        idx = rval_index(op)
    else: idx = 0
    return (base + idx + op.mem.disp) & MASK64

def rval_index(op):
    rn = md.reg_name(op.mem.index)
    v = get_reg(rn)
    v = apply_ext(v, op.ext)
    v = apply_shift(v, op.shift.type, op.shift.value, True)
    return v

def sx(v,bits):
    m=(1<<bits)-1; v&=m
    return v-(1<<bits) if (v>>(bits-1))&1 else v

def set_flags_add(a,b,res,w):
    m=(1<<w)-1
    Z[0]=1 if (res&m)==0 else 0; N[0]=(res>>(w-1))&1
    C[0]=1 if res>m else 0
    sa=(a>>(w-1))&1; sb=(b>>(w-1))&1; sr=(res>>(w-1))&1
    V[0]=1 if (sa==sb and sa!=sr) else 0

def set_flags_sub(a,b,res,w):
    m=(1<<w)-1; r=res&m
    Z[0]=1 if r==0 else 0; N[0]=(r>>(w-1))&1
    C[0]=1 if (a&m)>=(b&m) else 0
    sa=(a>>(w-1))&1; sb=(b>>(w-1))&1; sr=(r>>(w-1))&1
    V[0]=1 if (sa!=sb and sa!=sr) else 0

def set_flags_logic(res,w):
    r=res&((1<<w)-1)
    Z[0]=1 if r==0 else 0; N[0]=(r>>(w-1))&1; C[0]=0; V[0]=0

CC = {ARM64_CC_EQ:lambda:Z[0]==1, ARM64_CC_NE:lambda:Z[0]==0,
      ARM64_CC_HS:lambda:C[0]==1, ARM64_CC_LO:lambda:C[0]==0,
      ARM64_CC_MI:lambda:N[0]==1, ARM64_CC_PL:lambda:N[0]==0,
      ARM64_CC_VS:lambda:V[0]==1, ARM64_CC_VC:lambda:V[0]==0,
      ARM64_CC_HI:lambda:C[0]==1 and Z[0]==0, ARM64_CC_LS:lambda:C[0]==0 or Z[0]==1,
      ARM64_CC_GE:lambda:N[0]==V[0], ARM64_CC_LT:lambda:N[0]!=V[0],
      ARM64_CC_GT:lambda:Z[0]==0 and N[0]==V[0], ARM64_CC_LE:lambda:Z[0]==1 or N[0]!=V[0],
      ARM64_CC_AL:lambda:True, ARM64_CC_NV:lambda:True}


def wr_mem(a, data):
    mem.write(a, data)

# svc state
mmap_top = [0x50000000]
svc_log = []
def do_svc():
    nr = REG[8]; a0=REG[0]; a1=REG[1]; ret=0
    if nr==178: ret=0x40dc
    elif nr==222: ret=mmap_top[0]; mmap_top[0]+=(a1+0xfff)&~0xfff
    elif nr in (215,226): ret=0
    elif nr==113: wr_mem(a1, struct.pack('<qq',WALLTS[0],953000000))
    elif nr==63: ret=0
    elif nr in (56,48,98,79): ret=(-2)&MASK64
    else: svc_log.append(('UNK',nr,a0,a1))
    svc_log.append((nr,a0))
    REG[0]=ret&MASK64
def w(op): return 64 if md.reg_name(op.reg)[0] in 'x' else 32

# ---------------- main loop ----------------
def compute(query=None, digest=None):
    """Run the BIG VM once. query: raw query string (SM3 applied); or pass digest=32B directly.
       Returns key32 (32 bytes)."""
    global mem
    mem = Mem()
    mem.load(M0A, SNAP0); mem.load(M1A, SNAP1); mem.load(M2A, SNAP2); mem.load(C2A, SNAP3)
    if digest is None and query is not None:
        digest = hashlib.new('sm3', query.encode()).digest()
    if digest is not None:
        assert len(digest)==32
        mem.write(DIGEST_ADDR, digest)   # else: keep snapshot digest (r0/r1)
    for _i in range(31): REG[_i]=0
    for _k,_v in INIT_REGS.items():
        if _k=='sp': SP[0]=_v
        elif _k!='pc': REG[int(_k[1:])]=_v
    PC[0]=H711
    N[0]=Z[0]=C[0]=V[0]=0
    mmap_top[0]=0x50000000; del svc_log[:]
    step=0
    while True:
        pc = PC[0]
        if pc==H189: break
        i = decode(pc)
        ops = i.operands
        mn = i.mnemonic
        npc = pc+4
        step+=1
        if mn=='nop' or mn=='bti': pass
        elif mn=='dc':
            # dc zva, xN: zero the 64-byte block (DCZID_EL0=4 -> BS=64) containing xN.
            # unicorn fires 68 size-1 hook events: 4 duplicate at base, then base..base+63.
            zb = rval(ops[1]) & ~63
            mem.write(zb, bytes(64))
        elif mn=='b':
            if i.cc in (ARM64_CC_AL,ARM64_CC_NV,0) and not mn.startswith('b.'):
                npc = ops[0].imm
            else:
                npc = ops[0].imm if CC[i.cc]() else pc+4
        elif mn.startswith('b.'):
            npc = ops[0].imm if CC[i.cc]() else pc+4
        elif mn=='bl': REG[30]=pc+4; npc=ops[0].imm
        elif mn=='br': npc=rval(ops[0])
        elif mn=='blr': REG[30]=pc+4; npc=rval(ops[0])
        elif mn=='ret': npc = rval(ops[0]) if ops else REG[30]
        elif mn=='tbnz' or mn=='tbz':
            bit=ops[1].imm; v=rval(ops[0])
            tk = ((v>>bit)&1)==(1 if mn=='tbnz' else 0)
            npc = ops[2].imm if tk else pc+4
        elif mn=='cbz' or mn=='cbnz':
            v=rval(ops[0]); tk = (v==0) if mn=='cbz' else (v!=0)
            npc = ops[1].imm if tk else pc+4
        elif mn=='mov':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1]))
        elif mn=='movk':
            rn=md.reg_name(ops[0].reg); old=get_reg(rn)
            sh=ops[1].shift.value
            old &= ~(0xFFFF<<sh)&MASK64
            set_reg(rn, old | ((ops[1].imm&0xFFFF)<<sh))
        elif mn=='mvn':
            set_reg(md.reg_name(ops[0].reg), (~rval(ops[1]))&MASK64)
        elif mn=='neg':
            set_reg(md.reg_name(ops[0].reg), (-rval(ops[1]))&MASK64)
        elif mn=='add':
            set_reg(md.reg_name(ops[0].reg), (rval(ops[1])+rval(ops[2]))&MASK64)
        elif mn=='adds':
            a=rval(ops[1]); b=rval(ops[2]); r=a+b
            ww = 64 if md.reg_name(ops[1].reg)[0] in 'x' else 32
            set_flags_add(a,b,r,ww)
            set_reg(md.reg_name(ops[0].reg), r&MASK64)
        elif mn=='sub':
            set_reg(md.reg_name(ops[0].reg), (rval(ops[1])-rval(ops[2]))&MASK64)
        elif mn=='subs':
            a=rval(ops[1]); b=rval(ops[2]); r=(a-b)
            ww = 64 if md.reg_name(ops[1].reg)[0] in 'x' else 32
            set_flags_sub(a,b,r,ww)
            set_reg(md.reg_name(ops[0].reg), r&MASK64)
        elif mn=='cmp':
            a=rval(ops[0]); b=rval(ops[1])
            ww = 64 if md.reg_name(ops[0].reg)[0] in 'x' else 32
            set_flags_sub(a,b,a-b,ww)
        elif mn=='cmn':
            a=rval(ops[0]); b=rval(ops[1])
            ww = 64 if md.reg_name(ops[0].reg)[0] in 'x' else 32
            set_flags_add(a,b,a+b,ww)
        elif mn=='and':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1])&rval(ops[2]))
        elif mn=='ands':
            r=rval(ops[1])&rval(ops[2])
            ww = 64 if md.reg_name(ops[1].reg)[0] in 'x' else 32
            set_flags_logic(r,ww)
            set_reg(md.reg_name(ops[0].reg), r)
        elif mn=='tst':
            r=rval(ops[0])&rval(ops[1])
            ww = 64 if md.reg_name(ops[0].reg)[0] in 'x' else 32
            set_flags_logic(r,ww)
        elif mn=='orr':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1])|rval(ops[2]))
        elif mn=='eor':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1])^rval(ops[2]))
        elif mn=='bic':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1])&(~rval(ops[2])&MASK64))
        elif mn=='lsl' or mn=='lsr' or mn=='asr':
            a=rval(ops[1]); s=rval(ops[2])
            ww = 64 if md.reg_name(ops[1].reg)[0] in 'x' else 32
            m=(1<<ww)-1; a&=m; s%=ww
            if mn=='lsl': r=(a<<s)&m
            elif mn=='lsr': r=a>>s
            else:
                if (a>>(ww-1))&1: a|=MASK64^m
                r=(a>>s)&MASK64
            set_reg(md.reg_name(ops[0].reg), r)
        elif mn=='ror':
            a=rval(ops[1]); s=rval(ops[2])
            ww = 64 if md.reg_name(ops[1].reg)[0] in 'x' else 32
            m=(1<<ww)-1; a&=m; s%=ww
            set_reg(md.reg_name(ops[0].reg), ((a>>s)|(a<<(ww-s)))&m)
        elif mn=='ubfx':
            lsb=ops[2].imm; wd=ops[3].imm
            set_reg(md.reg_name(ops[0].reg), (rval(ops[1])>>lsb)&((1<<wd)-1))
        elif mn=='sbfx':
            lsb=ops[2].imm; wd=ops[3].imm
            v=(rval(ops[1])>>lsb)&((1<<wd)-1)
            set_reg(md.reg_name(ops[0].reg), sx(v,wd)&MASK64)
        elif mn=='sxtw':
            set_reg(md.reg_name(ops[0].reg), sx(rval(ops[1]),32)&MASK64)
        elif mn=='sxth':
            set_reg(md.reg_name(ops[0].reg), sx(rval(ops[1]),16)&MASK64)
        elif mn=='sxtb':
            set_reg(md.reg_name(ops[0].reg), sx(rval(ops[1]),8)&MASK64)
        elif mn=='uxtw' or mn=='uxth' or mn=='uxtb':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1]))
        elif mn=='smaddl':
            a=sx(rval(ops[1]),32); b=sx(rval(ops[2]),32)
            set_reg(md.reg_name(ops[0].reg), (rval(ops[3]) + a*b)&MASK64)
        elif mn=='smull':
            a=sx(rval(ops[1]),32); b=sx(rval(ops[2]),32)
            set_reg(md.reg_name(ops[0].reg), (a*b)&MASK64)
        elif mn=='mul':
            set_reg(md.reg_name(ops[0].reg), (rval(ops[1])*rval(ops[2]))&MASK64)
        elif mn=='madd':
            set_reg(md.reg_name(ops[0].reg), (rval(ops[3])+rval(ops[1])*rval(ops[2]))&MASK64)
        elif mn=='csel':
            set_reg(md.reg_name(ops[0].reg), rval(ops[1]) if CC[i.cc]() else rval(ops[2]))
        elif mn=='cset':
            set_reg(md.reg_name(ops[0].reg), 1 if CC[i.cc]() else 0)
        elif mn=='csetm':
            set_reg(md.reg_name(ops[0].reg), MASK64 if CC[i.cc]() else 0)
        elif mn=='cinc':
            set_reg(md.reg_name(ops[0].reg), (rval(ops[1]) + (0 if CC[i.cc]() else 1))&MASK64)
        elif mn=='adrp':
            set_reg(md.reg_name(ops[0].reg), ops[1].imm & MASK64)
        elif mn=='adr':
            set_reg(md.reg_name(ops[0].reg), ops[1].imm)
        elif mn=='mrs':
            set_reg(md.reg_name(ops[0].reg), TPIDR if 'tpidr' in i.op_str else (4 if 'dczid' in i.op_str else 0))
        elif mn=='svc':
            do_svc()
        elif mn in ('ldr','ldrb','ldrh','ldrsw','ldrsh','ldrsb'):
            o=ops[1]
            if o.type==ARM64_OP_IMM:
                a=o.imm; post=None
            else:
                a=maddr(o)
                post = ops[2].imm if len(ops)>2 else None
                if i.writeback and post is None:  # pre-index
                    set_reg(md.reg_name(o.mem.base), a)
            sz = 8 if md.reg_name(ops[0].reg)[0]=='x' else 4
            if mn=='ldrb': sz=1
            elif mn in ('ldrh','ldrsh'): sz=2
            elif mn in ('ldrsw','ldrsb'): sz = 4 if mn=='ldrsw' else 1
            v=int.from_bytes(mem.read(a,sz),'little')
            dst=md.reg_name(ops[0].reg)
            if mn=='ldrsw': v=sx(v,32)&MASK64
            elif mn=='ldrsh': v=sx(v,16)&(MASK64 if dst[0]=='x' else 0xFFFFFFFF)
            elif mn=='ldrsb': v=sx(v,8)&(MASK64 if dst[0]=='x' else 0xFFFFFFFF)
            set_reg(dst, v)
            if post is not None:
                set_reg(md.reg_name(o.mem.base), (get_reg(md.reg_name(o.mem.base))+post)&MASK64)
        elif mn in ('str','strb','strh'):
            o=ops[1]
            a=maddr(o)
            post = ops[2].imm if len(ops)>2 else None
            if i.writeback and post is None:
                set_reg(md.reg_name(o.mem.base), a)
            sz = 8 if md.reg_name(ops[0].reg)[0]=='x' else 4
            if mn=='strb': sz=1
            elif mn=='strh': sz=2
            wr_mem(a, (get_reg(md.reg_name(ops[0].reg))&((1<<(sz*8))-1)).to_bytes(sz,'little'))
            if post is not None:
                set_reg(md.reg_name(o.mem.base), (get_reg(md.reg_name(o.mem.base))+post)&MASK64)
        elif mn=='ldp':
            o=ops[2]; a=maddr(o)
            post = ops[3].imm if len(ops)>3 else None
            if i.writeback and post is None:
                set_reg(md.reg_name(o.mem.base), a)
            sz = 8 if md.reg_name(ops[0].reg)[0]=='x' else 4
            v1=int.from_bytes(mem.read(a,sz),'little'); v2=int.from_bytes(mem.read(a+sz,sz),'little')
            set_reg(md.reg_name(ops[0].reg), v1); set_reg(md.reg_name(ops[1].reg), v2)
            if post is not None:
                set_reg(md.reg_name(o.mem.base), (get_reg(md.reg_name(o.mem.base))+post)&MASK64)
        elif mn=='stp':
            o=ops[2]; a=maddr(o)
            post = ops[3].imm if len(ops)>3 else None
            if i.writeback and post is None:
                set_reg(md.reg_name(o.mem.base), a)
            sz = 8 if md.reg_name(ops[0].reg)[0]=='x' else 4
            m=(1<<(sz*8))-1
            wr_mem(a, (get_reg(md.reg_name(ops[0].reg))&m).to_bytes(sz,'little'))
            wr_mem(a+sz, (get_reg(md.reg_name(ops[1].reg))&m).to_bytes(sz,'little'))
            if post is not None:
                set_reg(md.reg_name(o.mem.base), (get_reg(md.reg_name(o.mem.base))+post)&MASK64)
        else:
            print('UNIMPL %s %s @%#x disp=%d'%(mn,i.op_str,pc,step)); break
        PC[0]=npc
        if step>2000000: raise RuntimeError('runaway')
    return mem.read(KEY32_ADDR, 32)

def medusa_f13_core(query):
    """f13 core: 16 bytes = key32[0:16] ^ key32[16:32]."""
    k32 = compute(query)
    return bytes(a^b for a,b in zip(k32[0:16], k32[16:32]))

def _sxtw(v):
    v &= 0xffffffff
    return v - (1 << 32) if v >= (1 << 31) else v

def medusa_f13_tail(core16):
    """f13 tail (bytes 16..19): gate network over core16[0:8].

    Reverse-engineered from progB slots 1304-1374 (libmetasec_ml.so 7.1.3.32):
      - 8-round loop reading core16[0:8] byte-by-byte, even/odd round paths
        built from NAND/NOR/XOR/SHL32/SHR32S gates, loop state in R2
        (init 0x20220420);
      - post-processing network mixing R2 with constants 0x6ab2878c (seed),
        8, and 52 (device env value), plus 0x00ff0000;
      - tail4 = low32(R2 | R8).
    Verified against 3 independent captures (r0/r2/r3).
    """
    M64 = (1 << 64) - 1
    R = [0] * 24
    R[2] = 0x20220420
    R[9] = 8           # loop bound
    R[17] = 0          # even/odd selector constant
    R[22] = 8
    R[23] = 0x6ab2878c
    def NAND(b0, b1, d): R[d] = (~(R[b1] & R[b0])) & M64
    def NOR (b0, b1, d): R[d] = (~(R[b1] | R[b0])) & M64
    def SHL32(b1, d, s): R[d] = _sxtw(((R[b1] & 0xffffffff) << s) & 0xffffffff) & M64
    def SHR32S(b1, s, d): R[d] = _sxtw((R[b1] & 0xffffffff) >> s) & M64
    for cnt in range(8):
        byte = core16[cnt]
        if cnt & 1:    # odd path (slots 1327-1339)
            R[8] = byte
            SHL32(2, 18, 11)
            NOR(18, 8, 12)
            NOR(18, 8, 8)
            SHR32S(2, 5, 18)
            NOR(12, 8, 8)
            R[2] = (R[18] ^ R[2]) & M64
            R[8] = (R[8] ^ R[2]) & M64
            NAND(17, 17, 2)
            NAND(8, 8, 8)
            NAND(8, 2, 8)
            NAND(8, 8, 2)
        else:          # even path (slots 1312-1326)
            SHL32(2, 8, 7)
            NOR(2, 2, 7)
            NOR(8, 2, 12)
            NOR(8, 8, 8)
            SHR32S(2, 3, 2)
            NOR(8, 7, 8)
            NAND(2, 2, 7)
            NOR(12, 8, 8)
            NAND(8, 8, 12)
            NAND(8, 7, 8)
            NAND(12, 2, 2)
            NAND(2, 8, 8)
            R[2] = byte
            R[2] = (R[2] ^ R[8]) & M64
    # post-processing (slots 1342-1371)
    R[8] = R[23] >> 42
    NAND(22, 22, 18)
    R[2] &= 0xffff
    NAND(8, 8, 9)
    NAND(8, 18, 8)
    NAND(9, 22, 9)
    NAND(9, 8, 8)
    R[9] = 52          # mem32[E18+12], device env value
    SHL32(8, 8, 0)
    NAND(9, 9, 18)
    NAND(8, 8, 12)
    NAND(18, 8, 8)
    NAND(9, 12, 9)
    NAND(22, 22, 18)
    NAND(8, 9, 8)
    R[9] = 0xff0000
    SHL32(8, 8, 16)
    NOR(9, 9, 9)
    NOR(8, 8, 8)
    NOR(8, 9, 8)
    R[9] = R[23] >> 56
    SHL32(9, 9, 0)
    NAND(9, 9, 12)
    NAND(18, 9, 9)
    NAND(22, 12, 18)
    NAND(9, 18, 9)
    SHL32(9, 9, 24)
    NOR(8, 9, 18)
    NOR(8, 9, 8)
    NOR(18, 8, 8)
    return ((R[2] | R[8]) & 0xffffffff).to_bytes(4, "little")

def medusa_f13(query):
    """f13 full: 20 bytes = core16 + tail4."""
    c16 = medusa_f13_core(query)
    return c16 + medusa_f13_tail(c16)

def medusa_f14(query):
    """f14 = SM3(query)[0:6]."""
    return hashlib.new('sm3', query.encode()).digest()[0:6]

if __name__ == '__main__':
    if len(sys.argv)>1:
        q = sys.argv[1]
        t0=time.time()
        print('f13core =', medusa_f13(q).hex(), ' (%.1fs)'%(time.time()-t0))
        print('f14     =', medusa_f14(q).hex())
        sys.exit(0)
    print('self-test...')
    # vector A: snapshot digest (r0/r1) — key32 must match exactly
    k = compute()
    assert k.hex()=='48b9ab07629541d0e563d0207f80d8d95406e2545cbab38d67d7d5b3c48876e1', k.hex()
    assert bytes(a^b for a,b in zip(k[0:16],k[16:32])).hex()=='1cbf49533e2ff25d82b40593bb08ae38'
    print('  r0 PASS  f13core=1cbf49533e2ff25d82b40593bb08ae38')
    assert medusa_f13_core('aid=1967&ts=1').hex()=='b17f33b17417aab8ad112eeecc20b185'
    assert medusa_f13_core('query=%E4%B8%89%E4%BD%93&offset=0&aid=1967').hex()=='af82bde0311cf322dc9f36ececc60d61'
    print('  r2/r3 PASS  f13core')
    assert medusa_f13_tail(bytes.fromhex('1cbf49533e2ff25d82b40593bb08ae38')).hex()=='fa213c08'
    assert medusa_f13_tail(bytes.fromhex('b17f33b17417aab8ad112eeecc20b185')).hex()=='3ed33c08'
    assert medusa_f13_tail(bytes.fromhex('af82bde0311cf322dc9f36ececc60d61')).hex()=='309e3c08'
    print('  r0/r2/r3 PASS  f13tail')
    full = medusa_f13('aid=1967')
    assert full.hex()=='1cbf49533e2ff25d82b40593bb08ae38fa213c08', full.hex()
    print('  FULL 20B PASS  f13='+full.hex())
    print('ALL PASS')
