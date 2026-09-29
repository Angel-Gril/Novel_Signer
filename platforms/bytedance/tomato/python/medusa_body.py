# -*- coding: utf-8 -*-
# medusa_body.py — X-Medusa body (raw[26:], 225B) legacy snapshot calculator.
#
# This file reproduces the older 12a2a000 snapshot and its captured 225-byte
# vectors. It is intentionally not advertised as the current v04.09.09.01
# online signer. The current VM9 path has different 228/803/804-byte branches.
# Direct port of medusa_emu7/emu9 (unicorn snapshot emulation) to a pure-Python
# ARM64 interpreter. No unicorn / unidbg / Android runtime.
# Memory: prog@0x12a2a000 r1@0xe4ff2000 r2@0x12280000 r3@0x12800000
#         r4@0x11EC0000(first 0x3C0000) chain@0xfffc0000 stack zeroed
# svc: chain-region -> JNI by imm; elsewhere -> linux syscall by x8.
# Stop: PC==0 or PC==SENT(0xDEAD0000). Output: 225B ping-pong buffer.
import struct, os, sys, time
from capstone import *
from capstone.arm64_const import *

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'udghook') + os.sep
C2A = 0x11EC0000
R2A = 0x12280000
R1A = 0xe4ff2000
R3A = 0x12800000
PROGB = 0x12a2a000
STACKA, STACKS = 0x70000000, 0x100000
SENT = 0xDEAD0000
CHA = 0xfffc0000
TPIDR = 0xe4fff718
MASK64 = (1 << 64) - 1
WALLTS = [1790085004]  # wall clock fed to svc 96/113 (frozen harness value; override for live)

ROUNDS = {
    0: dict(suf='',    ex14=0x9, ex15=0xa1, gold='_gold0.txt', out=0x122a1400),
    1: dict(suf='_e2', ex14=0x6, ex15=0x9d, gold='_g1.txt',    out=0x122a1000),
    2: dict(suf='_e3', ex14=0x9, ex15=0x76, gold='_g2.txt',    out=0x122a1400),
    3: dict(suf='_e4', ex14=0x2, ex15=0x4b, gold='_g3.txt',    out=0x122a1000),
}

_blobs = {}
def blob(name):
    b = _blobs.get(name)
    if b is None:
        b = open(D + name, 'rb').read()
        _blobs[name] = b
    return b

class Mem:
    PS = 0x1000
    def __init__(self):
        self.pages = {}
    def _pg(self, a):
        k = a & ~(self.PS - 1)
        p = self.pages.get(k)
        if p is None:
            p = bytearray(self.PS); self.pages[k] = p
        return p
    def load(self, a, data):
        off = 0
        while off < len(data):
            aa = a + off
            k = aa & ~(self.PS - 1); o = aa - k
            n = min(self.PS - o, len(data) - off)
            p = self._pg(k)
            p[o:o+n] = data[off:off+n]
            off += n
    def read(self, a, n):
        out = bytearray()
        while n > 0:
            k = a & ~(self.PS - 1); o = a - k
            c = min(self.PS - o, n)
            p = self.pages.get(k)
            out += p[o:o+c] if p is not None else bytes(c)
            a += c; n -= c
        return bytes(out)
    def write(self, a, data):
        if WATCH is not None and a < WATCH[1] and a + len(data) > WATCH[0] and ins_on[0]:
            WLOG.append((ins_n[0], PC[0], a, bytes(data)))
        n = len(data); off = 0
        while off < n:
            aa = a + off
            k = aa & ~(self.PS - 1); o = aa - k
            c = min(self.PS - o, n - off)
            p = self._pg(k)
            p[o:o+c] = data[off:off+c]
            off += c

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
_rnm = md.reg_name
def rnm(r):
    n = _rnm(r)
    return 'x29' if n == 'fp' else ('x30' if n == 'lr' else n)
dcache = {}
mem = None
WATCH = None
WLOG = []
def decode(a):
    i = dcache.get(a)
    if i is None:
        b = mem.read(a, 4)
        i = next(md.disasm(b, a))
        dcache[a] = i
    return i

REG = [0]*31
VREG = [0]*32          # 128-bit vector regs (only trivial ops supported)
SP = [0]
PC = [0]
N = [0]; Z = [0]; C = [0]; V = [0]

def regidx(rname):
    if rname in ('sp', 'wsp'): return 'sp'
    if rname == 'fp': return 29
    if rname == 'lr': return 30
    if rname in ('xzr', 'wzr'): return 'zr'
    return int(rname[1:])

def get_reg(rname):
    t = regidx(rname)
    if t == 'zr': return 0
    v = SP[0] if t == 'sp' else REG[t]
    if rname[0] == 'w': v &= 0xFFFFFFFF
    return v

def set_reg(rname, val):
    val &= MASK64
    t = regidx(rname)
    if t == 'zr': return
    if rname[0] == 'w': val &= 0xFFFFFFFF
    if t == 'sp': SP[0] = val
    else: REG[t] = val

EXT = {ARM64_EXT_UXTB:8, ARM64_EXT_UXTH:16, ARM64_EXT_UXTW:32, ARM64_EXT_UXTX:64,
       ARM64_EXT_SXTB:-8, ARM64_EXT_SXTH:-16, ARM64_EXT_SXTW:-32, ARM64_EXT_SXTX:-64}
def apply_ext(v, ext):
    if ext == 0: return v
    bits = EXT[ext]
    if bits > 0: return v & ((1 << bits) - 1)
    b = -bits; m = (1 << b) - 1; v &= m
    return v | (~m & MASK64) if (v >> (b-1)) & 1 else v

def apply_shift(v, st, sv, is64):
    if st == 0 or sv == 0: return v
    if st == ARM64_SFT_LSL: return (v << sv) & MASK64
    if st == ARM64_SFT_LSR: return (v & (MASK64 if is64 else 0xFFFFFFFF)) >> sv
    if st == ARM64_SFT_ASR:
        w = 64 if is64 else 32; v &= (1 << w) - 1
        if (v >> (w-1)) & 1: v |= MASK64 ^ ((1 << w) - 1)
        return (v >> sv) & MASK64
    if st == ARM64_SFT_ROR:
        w = 64 if is64 else 32; v &= (1 << w) - 1
        return ((v >> sv) | (v << (w-sv))) & ((1 << w) - 1)
    return v

def rval(op):
    if op.type == ARM64_OP_IMM:
        v = op.imm & MASK64
        if op.shift.type and op.shift.value:
            v = apply_shift(v, op.shift.type, op.shift.value, True)
        return v
    if op.type == ARM64_OP_REG:
        rn = rnm(op.reg)
        v = get_reg(rn)
        v = apply_ext(v, op.ext)
        is64 = not rn.startswith('w')
        v = apply_shift(v, op.shift.type, op.shift.value, is64)
        return v
    raise Exception('bad rval op')

def rval_index(op):
    rn = rnm(op.mem.index)
    v = get_reg(rn)
    v = apply_ext(v, op.ext)
    v = apply_shift(v, op.shift.type, op.shift.value, True)
    return v

def maddr(op):
    base = get_reg(rnm(op.mem.base)) if op.mem.base else 0
    idx = rval_index(op) if op.mem.index else 0
    return (base + idx + op.mem.disp) & MASK64

def sx(v, bits):
    m = (1 << bits) - 1; v &= m
    return v - (1 << bits) if (v >> (bits-1)) & 1 else v

def set_flags_add(a, b, res, w):
    m = (1 << w) - 1
    Z[0] = 1 if (res & m) == 0 else 0; N[0] = (res >> (w-1)) & 1
    C[0] = 1 if res > m else 0
    sa = (a >> (w-1)) & 1; sb = (b >> (w-1)) & 1; sr = (res >> (w-1)) & 1
    V[0] = 1 if (sa == sb and sa != sr) else 0

def set_flags_sub(a, b, res, w):
    m = (1 << w) - 1; r = res & m
    Z[0] = 1 if r == 0 else 0; N[0] = (r >> (w-1)) & 1
    C[0] = 1 if (a & m) >= (b & m) else 0
    sa = (a >> (w-1)) & 1; sb = (b >> (w-1)) & 1; sr = (r >> (w-1)) & 1
    V[0] = 1 if (sa != sb and sa != sr) else 0

def set_flags_logic(res, w):
    r = res & ((1 << w) - 1)
    Z[0] = 1 if r == 0 else 0; N[0] = (r >> (w-1)) & 1; C[0] = 0; V[0] = 0

CC = {ARM64_CC_EQ: lambda: Z[0] == 1, ARM64_CC_NE: lambda: Z[0] == 0,
      ARM64_CC_HS: lambda: C[0] == 1, ARM64_CC_LO: lambda: C[0] == 0,
      ARM64_CC_MI: lambda: N[0] == 1, ARM64_CC_PL: lambda: N[0] == 0,
      ARM64_CC_VS: lambda: V[0] == 1, ARM64_CC_VC: lambda: V[0] == 0,
      ARM64_CC_HI: lambda: C[0] == 1 and Z[0] == 0, ARM64_CC_LS: lambda: C[0] == 0 or Z[0] == 1,
      ARM64_CC_GE: lambda: N[0] == V[0], ARM64_CC_LT: lambda: N[0] != V[0],
      ARM64_CC_GT: lambda: Z[0] == 0 and N[0] == V[0], ARM64_CC_LE: lambda: Z[0] == 1 or N[0] != V[0],
      ARM64_CC_AL: lambda: True, ARM64_CC_NV: lambda: True}

# ---------------- svc simulation (JNI + linux), ported from medusa_emu7/9 ----------------
VER = b"7.1.3.32"
jni_objs = {}
next_handle = [0xfffee000]
def new_handle(kind, val=None):
    h = next_handle[0]; next_handle[0] += 0x10
    jni_objs[h] = (kind, val)
    return h

class JRandom:
    def __init__(self, seed): self.s = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def next(self, bits):
        self.s = (self.s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return self.s >> (48 - bits)
    def next_bytes(self, n):
        out = bytearray(); i = 0
        while i < n:
            rnd = self.next(32); k = min(n - i, 4)
            for j in range(k):
                out.append(rnd & 0xff); rnd >>= 8
            i += k
        return bytes(out)
URAND = JRandom(42).next_bytes(65536)
fdtab = {}
nextfd = [100]
mmap_top = [0x50000000]
svc_log = []

def cstr_at(a):
    b = mem.read(a, 256)
    return b.split(b"\x00")[0]

def do_svc(pc):
    global mem
    insn = int.from_bytes(mem.read(pc, 4), 'little')
    imm = (insn >> 5) & 0xffff
    if CHA <= pc < CHA + len(blob('dump_pe_12d40000_chain.bin')):
        # JNI dispatch (unidbg registerSvc index, imm = 255 + idx)
        x1 = REG[1]; x2 = REG[2]; x3 = REG[3]; x4 = REG[4]
        rv = 0
        if imm == 489:      # GetEnv
            mem.write(x1, struct.pack("<Q", 0xfffe1640)); rv = 0
        elif imm == 480:    # ExceptionCheck
            rv = 0
        elif imm == 367:    # CallStaticObjectMethodV MS.b -> "7.1.3.32"
            rv = new_handle("str", VER)
        elif imm == 439:    # NewStringUTF
            rv = new_handle("str", bytes(cstr_at(x1)))
        elif imm == 285:    # GetMethodID
            nm = cstr_at(x2); sg = cstr_at(x3)
            rv = 0x318b4ca9 if nm == b"getBytes" else new_handle("mid", (nm, sg))
        elif imm == 287:    # CallObjectMethodV
            obj = jni_objs.get(x1)
            rv = new_handle("bytes", obj[1] if obj and obj[0] == "str" else b"")
        elif imm == 416:    # GetArrayLength
            obj = jni_objs.get(x1)
            rv = len(obj[1]) if obj and obj[0] == "bytes" else 0
        elif imm == 452:    # GetByteArrayRegion(arr, start, len, dest)
            obj = jni_objs.get(x1)
            data = obj[1] if obj and obj[0] == "bytes" else b""
            st = x2 & 0xffffffff; ln = x3 & 0xffffffff
            mem.write(x4, data[st:st+ln]); rv = 0
        elif imm == 258:    # FindClass
            rv = new_handle("class", cstr_at(x1))
        elif imm == 273:    # NewGlobalRef
            rv = x1
        elif imm == 275:    # DeleteLocalRef
            rv = 0
        elif imm == 283:    # GetObjectClass
            rv = new_handle("class", b"?")
        elif imm == 267:    # ExceptionOccurred
            rv = 0
        elif imm == 269:    # ExceptionClear
            rv = 0
        svc_log.append(('jni', imm, rv & MASK64))
        REG[0] = rv & MASK64
        return
    nr = REG[8]; a0 = REG[0]; a1 = REG[1]
    ret = 0
    if nr == 178: ret = 0
    elif nr == 172 or nr == 173: ret = 16600
    elif nr == 80:          # fstat
        st = bytearray(128)
        struct.pack_into("<I", st, 16, 0o0100644); struct.pack_into("<q", st, 48, 1048576)
        struct.pack_into("<i", st, 56, 4096); struct.pack_into("<q", st, 64, 2048)
        mem.write(a1, bytes(st)); ret = 0
    elif nr == 222:         # mmap
        ln = (a1 + 0xfff) & ~0xfff
        ret = mmap_top[0]; mmap_top[0] += ln
    elif nr in (215, 226): ret = 0
    elif nr == 113:         # clock_gettime
        if (a0 & 7) == 0: mem.write(a1, struct.pack("<qq", WALLTS[0] * 1000 // 1000, (WALLTS[0] * 1000 % 1000) * 1000000))
        else: mem.write(a1, struct.pack("<qq", 123456789, 0))
    elif nr == 96:
        mem.write(a0, struct.pack("<q", WALLTS[0]))
    elif nr == 278:         # getrandom
        mem.write(a0, bytes((i*7+13) & 0xff for i in range(a1))); ret = a1
    elif nr == 63:          # read
        cnt = REG[2]
        path = fdtab.get(a0)
        if path is not None and path[0] == b"/dev/urandom":
            off = path[1]
            data = URAND[off:off+cnt]
            if len(data) < cnt: data = data + JRandom(43).next_bytes(cnt - len(data))
            fdtab[a0] = (path[0], off + len(data))
            mem.write(a1, data); ret = len(data)
        else:
            ret = 0
    elif nr == 56:          # openat
        path = cstr_at(a1)
        if path == b"/dev/urandom":
            fd = nextfd[0]; nextfd[0] += 1; fdtab[fd] = (path, 0); ret = fd
        else:
            ret = (-2) & MASK64
    elif nr == 98: ret = 0  # futex
    elif nr in (48, 79): ret = (-2) & MASK64
    svc_log.append(('sys', nr, ret & MASK64))
    REG[0] = ret & MASK64

# ---------------- main interpreter loop ----------------
REGS_BASE = {0:0x12a2a000, 1:0xe4ff2930, 2:0xe4ffe9f8, 3:0x4, 4:0, 5:0x40, 6:0x3f, 7:0,
             8:0x1256cb88, 9:0x6150, 10:0x4d0, 11:0xe4ff8470, 12:0, 13:0xe4ff2940,
             16:0x12635220, 17:0x1210c640, 18:0x12282020, 19:0xe4ff2930,
             20:0x128ff888, 21:0xe4ff2930, 22:0xe4fff718, 23:0xe4ff8980, 24:0x12623ee8,
             25:0xe4ff8b00, 26:0xe4ff8a80, 27:0, 28:0}

import collections
ring = collections.deque(maxlen=64)
TRC = os.environ.get('MTRC', '')
trc_f = None
handler_set = set()
trc_last = [None]
def trc_rec(pc):
    if not TRC or pc not in handler_set: return
    pcidx = int.from_bytes(mem.read(0xe4ff2930, 4), 'little')
    if (pcidx, pc) != trc_last[0]:
        trc_f.write(('%d %#x' % (pcidx, pc)) + chr(10))
        trc_last[0] = (pcidx, pc)
DBG = os.environ.get('MDBG','') != ''
ins_f = open(os.environ.get('MINSF', '_ins_py.txt'), 'w', buffering=65536) if os.environ.get('MINS') else None
ins_on = [False]
ins_n = [0]

def run(pc0, maxstep=60000000):
    step = 0
    while True:
        pc = PC[0]
        if pc == 0 or pc == SENT:
            return step
        i = decode(pc)
        ops = i.operands
        trc_rec(pc)
        if ins_f is not None:
            if ins_on[0]:
                ins_f.write(('%#x %s %s' % (pc, i.mnemonic, i.op_str)) + chr(10))
                ins_n[0] += 1
                if ins_n[0] > int(os.environ.get('MINS_MAX', '3000000')): raise RuntimeError('ins cap')
            elif pc == 0x1256ca78 and int.from_bytes(mem.read(0xe4ff2930, 4), 'little') == 175:
                ins_on[0] = True
        if pc == 0x125153d4 and DBG:
            print('  @sz w0=%#x' % (REG[0]&0xffffffff))
        if pc == 0x12515410 and DBG:
            print('  @cinc w8=%#x Z=%d' % (REG[8]&0xffffffff, Z[0]))
        if pc in (0x12513ca4, 0x12513c8c) and DBG:
            print('  @%#x [x20]=%#x' % (pc, int.from_bytes(mem.read(REG[20]&MASK64,4),'little')))
        if pc == 0x12513bac and DBG:
            print('  @acc x0=%#x x20=%#x' % (REG[0], REG[20]))
        if pc == 0x12507b4c and DBG:
            print('  @csel w24=%#x w25=%#x N=%d Z=%d C=%d V=%d' % (REG[24]&0xffffffff, REG[25]&0xffffffff, N[0], Z[0], C[0], V[0]))
        if pc in (0x12508e98, 0x12508e9c, 0x125697d4, 0x125697d8) and DBG:
            print('  @%#x x0=%#x x1=%#x x8=%#x x19=%#x x20=%#x [x0+0xc]=%s' % (pc, REG[0], REG[1], REG[8], REG[19], REG[20], mem.read((REG[0]+0xc)&MASK64,4).hex()))
        if pc in (0x1252b5fc, 0x1252b600, 0x1252b5f0) and DBG:
            print('  @%#x sp=%#x x30=%#x [sp+8]=%s x0=%#x' % (pc, SP[0], REG[30], mem.read(SP[0]+8,8).hex(), REG[0]))
        mn = i.mnemonic
        npc = pc + 4
        step += 1
        ring.append((pc, mn, i.op_str))
        if mn in ('nop', 'bti', 'paciasp', 'pacibsp', 'autiasp', 'autibsp', 'xpaclri', 'paciaz', 'pacibz', 'autiaz', 'autibz', 'hint', 'yield', 'wfe', 'wfi', 'sev', 'sevl'): pass
        elif mn == 'udf':
            print('UDF @%#x step=%d' % (pc, step))
            for e in list(ring)[-24:]: print('   %#x %s %s' % e)
            raise RuntimeError('udf @%#x' % pc)
        elif mn == 'dc':
            zb = rval(ops[1]) & ~63
            mem.write(zb, bytes(64))
        elif mn == 'b' or mn.startswith('b.'):
            _cc = i.cc
            npc = ops[0].imm if (_cc in (0, ARM64_CC_AL, ARM64_CC_NV) or CC[_cc]()) else pc + 4
        elif mn == 'bl': REG[30] = pc + 4; npc = ops[0].imm
        elif mn == 'br': npc = rval(ops[0])
        elif mn == 'blr': REG[30] = pc + 4; npc = rval(ops[0])
        elif mn == 'ret': npc = rval(ops[0]) if ops else REG[30]
        elif mn == 'tbnz' or mn == 'tbz':
            bit = ops[1].imm; v = rval(ops[0])
            tk = ((v >> bit) & 1) == (1 if mn == 'tbnz' else 0)
            npc = ops[2].imm if tk else pc + 4
        elif mn == 'cbz' or mn == 'cbnz':
            v = rval(ops[0]); tk = (v == 0) if mn == 'cbz' else (v != 0)
            npc = ops[1].imm if tk else pc + 4
        elif mn == 'mov':
            set_reg(rnm(ops[0].reg), rval(ops[1]))
        elif mn == 'movz':
            set_reg(rnm(ops[0].reg), (ops[1].imm & 0xFFFF) << ops[1].shift.value)
        elif mn == 'movk':
            rn = rnm(ops[0].reg); old = get_reg(rn)
            sh = ops[1].shift.value
            old &= ~(0xFFFF << sh) & MASK64
            set_reg(rn, old | ((ops[1].imm & 0xFFFF) << sh))
        elif mn == 'mvn' or mn == 'movn':
            set_reg(rnm(ops[0].reg), (~rval(ops[1])) & MASK64)
        elif mn == 'neg':
            set_reg(rnm(ops[0].reg), (-rval(ops[1])) & MASK64)
        elif mn == 'negs':
            a = 0; b = rval(ops[1]); r = -b
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            set_flags_sub(0, b, r, ww)
            set_reg(rnm(ops[0].reg), r & MASK64)
        elif mn == 'add':
            set_reg(rnm(ops[0].reg), (rval(ops[1]) + rval(ops[2])) & MASK64)
        elif mn == 'adds':
            a = rval(ops[1]); b = rval(ops[2]); r = a + b
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            set_flags_add(a, b, r, ww)
            set_reg(rnm(ops[0].reg), r & MASK64)
        elif mn == 'sub':
            set_reg(rnm(ops[0].reg), (rval(ops[1]) - rval(ops[2])) & MASK64)
        elif mn == 'subs':
            a = rval(ops[1]); b = rval(ops[2]); r = a - b
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            set_flags_sub(a, b, r, ww)
            set_reg(rnm(ops[0].reg), r & MASK64)
        elif mn == 'cmp':
            a = rval(ops[0]); b = rval(ops[1])
            ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
            set_flags_sub(a, b, a - b, ww)
        elif mn == 'cmn':
            a = rval(ops[0]); b = rval(ops[1])
            ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
            set_flags_add(a, b, a + b, ww)
        elif mn == 'ccmp' or mn == 'ccmn':
            if CC[i.cc]():
                a = rval(ops[0]); b = rval(ops[1])
                ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
                if mn == 'ccmp': set_flags_sub(a, b, a - b, ww)
                else: set_flags_add(a, b, a + b, ww)
            else:
                nz = ops[2].imm
                N[0] = (nz >> 3) & 1; Z[0] = (nz >> 2) & 1; C[0] = (nz >> 1) & 1; V[0] = nz & 1
        elif mn == 'and':
            set_reg(rnm(ops[0].reg), rval(ops[1]) & rval(ops[2]))
        elif mn == 'ands':
            r = rval(ops[1]) & rval(ops[2])
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            set_flags_logic(r, ww)
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'tst':
            r = rval(ops[0]) & rval(ops[1])
            ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
            set_flags_logic(r, ww)
        elif mn == 'orr':
            set_reg(rnm(ops[0].reg), rval(ops[1]) | rval(ops[2]))
        elif mn == 'orn':
            set_reg(rnm(ops[0].reg), rval(ops[1]) | (~rval(ops[2]) & MASK64))
        elif mn == 'eor':
            set_reg(rnm(ops[0].reg), rval(ops[1]) ^ rval(ops[2]))
        elif mn == 'eon':
            set_reg(rnm(ops[0].reg), rval(ops[1]) ^ (~rval(ops[2]) & MASK64))
        elif mn == 'bic':
            set_reg(rnm(ops[0].reg), rval(ops[1]) & (~rval(ops[2]) & MASK64))
        elif mn == 'bics':
            r = rval(ops[1]) & (~rval(ops[2]) & MASK64)
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            set_flags_logic(r, ww)
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'lsl' or mn == 'lsr' or mn == 'asr':
            a = rval(ops[1]); s = rval(ops[2])
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            m = (1 << ww) - 1; a &= m; s %= ww
            if mn == 'lsl': r = (a << s) & m
            elif mn == 'lsr': r = a >> s
            else:
                if (a >> (ww-1)) & 1: a |= MASK64 ^ m
                r = (a >> s) & MASK64
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'ror':
            a = rval(ops[1]); s = rval(ops[2])
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            m = (1 << ww) - 1; a &= m; s %= ww
            set_reg(rnm(ops[0].reg), ((a >> s) | (a << (ww - s))) & m)
        elif mn == 'extr':
            a = rval(ops[1]); b = rval(ops[2]); lsb = ops[3].imm
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            m = (1 << ww) - 1
            set_reg(rnm(ops[0].reg), ((((a & m) << ww) | (b & m)) >> lsb) & m)
        elif mn == 'ubfx':
            lsb = ops[2].imm; wd = ops[3].imm
            set_reg(rnm(ops[0].reg), (rval(ops[1]) >> lsb) & ((1 << wd) - 1))
        elif mn == 'sbfx':
            lsb = ops[2].imm; wd = ops[3].imm
            v = (rval(ops[1]) >> lsb) & ((1 << wd) - 1)
            set_reg(rnm(ops[0].reg), sx(v, wd) & MASK64)
        elif mn == 'sbfiz':
            lsb = ops[2].imm; wd = ops[3].imm
            v = rval(ops[1]) & ((1 << wd) - 1)
            set_reg(rnm(ops[0].reg), (sx(v, wd) << lsb) & MASK64)
        elif mn == 'ubfiz':
            lsb = ops[2].imm; wd = ops[3].imm
            v = rval(ops[1]) & ((1 << wd) - 1)
            set_reg(rnm(ops[0].reg), (v << lsb) & MASK64)
        elif mn == 'bfi':
            lsb = ops[2].imm; wd = ops[3].imm
            m = ((1 << wd) - 1) << lsb
            rn = rnm(ops[0].reg)
            set_reg(rn, (get_reg(rn) & ~m) | ((rval(ops[1]) << lsb) & m))
        elif mn == 'bfxil':
            lsb = ops[2].imm; wd = ops[3].imm
            m = (1 << wd) - 1
            rn = rnm(ops[0].reg)
            set_reg(rn, (get_reg(rn) & ~m) | ((rval(ops[1]) >> lsb) & m))
        elif mn == 'sxtw':
            set_reg(rnm(ops[0].reg), sx(rval(ops[1]), 32) & MASK64)
        elif mn == 'sxth':
            set_reg(rnm(ops[0].reg), sx(rval(ops[1]), 16) & MASK64)
        elif mn == 'sxtb':
            set_reg(rnm(ops[0].reg), sx(rval(ops[1]), 8) & MASK64)
        elif mn == 'uxtw' or mn == 'uxth' or mn == 'uxtb':
            set_reg(rnm(ops[0].reg), rval(ops[1]))
        elif mn == 'smaddl':
            a = sx(rval(ops[1]), 32); b = sx(rval(ops[2]), 32)
            set_reg(rnm(ops[0].reg), (rval(ops[3]) + a * b) & MASK64)
        elif mn == 'smull':
            a = sx(rval(ops[1]), 32); b = sx(rval(ops[2]), 32)
            set_reg(rnm(ops[0].reg), (a * b) & MASK64)
        elif mn == 'smsubl':
            a = sx(rval(ops[1]), 32); b = sx(rval(ops[2]), 32)
            set_reg(rnm(ops[0].reg), (rval(ops[3]) - a * b) & MASK64)
        elif mn == 'umaddl':
            a = rval(ops[1]) & 0xFFFFFFFF; b = rval(ops[2]) & 0xFFFFFFFF
            set_reg(rnm(ops[0].reg), (rval(ops[3]) + a * b) & MASK64)
        elif mn == 'umull':
            a = rval(ops[1]) & 0xFFFFFFFF; b = rval(ops[2]) & 0xFFFFFFFF
            set_reg(rnm(ops[0].reg), (a * b) & MASK64)
        elif mn == 'mul':
            set_reg(rnm(ops[0].reg), (rval(ops[1]) * rval(ops[2])) & MASK64)
        elif mn == 'madd':
            set_reg(rnm(ops[0].reg), (rval(ops[3]) + rval(ops[1]) * rval(ops[2])) & MASK64)
        elif mn == 'msub':
            set_reg(rnm(ops[0].reg), (rval(ops[3]) - rval(ops[1]) * rval(ops[2])) & MASK64)
        elif mn == 'mneg':
            set_reg(rnm(ops[0].reg), (-rval(ops[1]) * rval(ops[2])) & MASK64)
        elif mn == 'udiv' or mn == 'sdiv':
            a = rval(ops[1]); b = rval(ops[2])
            ww = 64 if rnm(ops[1].reg)[0] == 'x' else 32
            m = (1 << ww) - 1
            if mn == 'udiv':
                r = 0 if b == 0 else (a & m) // (b & m)
            else:
                aa = sx(a, ww); bb = sx(b, ww)
                r = 0 if bb == 0 else int(abs(aa) // abs(bb)) * (1 if (aa < 0) == (bb < 0) else -1)
            set_reg(rnm(ops[0].reg), r & m)
        elif mn == 'rbit':
            a = rval(ops[1])
            ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
            r = 0
            for _b in range(ww):
                r = (r << 1) | (a & 1); a >>= 1
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'clz':
            a = rval(ops[1])
            ww = 64 if rnm(ops[0].reg)[0] == 'x' else 32
            a &= (1 << ww) - 1
            r = ww if a == 0 else ww - a.bit_length()
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'rev' or mn == 'rev32' or mn == 'rev16':
            a = rval(ops[1])
            is64 = rnm(ops[0].reg)[0] == 'x'
            ww = 64 if is64 else 32
            a &= (1 << ww) - 1
            grp = {'rev': 8 if is64 else 4, 'rev32': 4, 'rev16': 2}[mn]
            r = 0; nb = ww // 8
            bs = [(a >> (8 * k)) & 0xff for k in range(nb)]
            out = [0] * nb
            for g in range(nb // grp):
                chunk = bs[g*grp:(g+1)*grp]
                out[g*grp:(g+1)*grp] = chunk[::-1]
            for k in range(nb): r |= out[k] << (8 * k)
            set_reg(rnm(ops[0].reg), r)
        elif mn == 'csel':
            set_reg(rnm(ops[0].reg), rval(ops[1]) if CC[i.cc]() else rval(ops[2]))
        elif mn == 'csinc':
            set_reg(rnm(ops[0].reg), rval(ops[1]) if CC[i.cc]() else (rval(ops[2]) + 1) & MASK64)
        elif mn == 'csinv':
            set_reg(rnm(ops[0].reg), rval(ops[1]) if CC[i.cc]() else (~rval(ops[2]) & MASK64))
        elif mn == 'csneg':
            set_reg(rnm(ops[0].reg), rval(ops[1]) if CC[i.cc]() else (-rval(ops[2]) & MASK64))
        elif mn == 'cneg':
            set_reg(rnm(ops[0].reg), (-rval(ops[1]) & MASK64) if CC[i.cc]() else rval(ops[1]))
        elif mn == 'cset':
            set_reg(rnm(ops[0].reg), 1 if CC[i.cc]() else 0)
        elif mn == 'csetm':
            set_reg(rnm(ops[0].reg), MASK64 if CC[i.cc]() else 0)
        elif mn == 'cinc':
            set_reg(rnm(ops[0].reg), (rval(ops[1]) + (1 if CC[i.cc]() else 0)) & MASK64)
        elif mn == 'cinv':
            set_reg(rnm(ops[0].reg), (~rval(ops[1]) & MASK64) if CC[i.cc]() else rval(ops[1]))
        elif mn == 'adrp':
            set_reg(rnm(ops[0].reg), ops[1].imm & MASK64)
        elif mn == 'adr':
            set_reg(rnm(ops[0].reg), ops[1].imm)
        elif mn == 'mrs':
            if 'nzcv' in i.op_str:
                set_reg(rnm(ops[0].reg), (N[0] << 31) | (Z[0] << 30) | (C[0] << 29) | (V[0] << 28))
            else:
                set_reg(rnm(ops[0].reg), TPIDR if 'tpidr' in i.op_str else (4 if 'dczid' in i.op_str else 0))
        elif mn == 'msr':
            if 'nzcv' in i.op_str:
                v = rval(ops[1])
                N[0] = (v >> 31) & 1; Z[0] = (v >> 30) & 1; C[0] = (v >> 29) & 1; V[0] = (v >> 28) & 1
        elif mn == 'svc':
            do_svc(pc)
        elif mn == 'dup':
            # dup vd.T, wn  (T like 16b/8h/4s/2d)
            vn = rnm(ops[0].reg)
            sz = {'16b': 1, '8b': 1, '8h': 2, '4h': 2, '4s': 4, '2s': 4, '2d': 8, '1d': 8}[i.op_str.split(',')[0].split('.')[1]]
            el = get_reg(rnm(ops[1].reg)) & ((1 << (sz * 8)) - 1)
            q = 0
            for k in range(16 // sz): q |= el << (sz * 8 * k)
            VREG[int(vn[1:])] = q
        elif mn == 'shl' or mn == 'ushr':
            d0 = rnm(ops[0].reg); d1 = rnm(ops[1].reg)
            assert d0[0] == 'd' and d1[0] == 'd'
            if mn == 'shl': VREG[int(d0[1:])] = (VREG[int(d1[1:])] << ops[2].imm) & MASK64
            else: VREG[int(d0[1:])] = (VREG[int(d1[1:])] & MASK64) >> ops[2].imm
        elif mn == 'umulh':
            set_reg(rnm(ops[0].reg), ((rval(ops[1]) * rval(ops[2])) >> 64) & MASK64)
        elif mn == 'smulh':
            a = sx(rval(ops[1]), 64); b = sx(rval(ops[2]), 64)
            set_reg(rnm(ops[0].reg), ((a * b) >> 64) & MASK64)
        elif mn == 'fmov':
            d0 = rnm(ops[0].reg)
            if ops[1].type == ARM64_OP_FP:
                if d0[0] == 's': VREG[int(d0[1:])] = struct.unpack('<I', struct.pack('<f', ops[1].fp))[0]
                else: VREG[int(d0[1:])] = struct.unpack('<Q', struct.pack('<d', ops[1].fp))[0]
            else:
                d1 = rnm(ops[1].reg)
                if d0[0] in 'bhsdq' and d1[0] in 'wx':
                    sz = {'b': 1, 'h': 2, 's': 4, 'd': 8}[d0[0]]
                    VREG[int(d0[1:])] = get_reg(d1) & ((1 << (sz * 8)) - 1)
                elif d0[0] in 'wx' and d1[0] in 'bhsdq':
                    sz = {'b': 1, 'h': 2, 's': 4, 'd': 8}[d1[0]]
                    set_reg(d0, VREG[int(d1[1:])] & ((1 << (sz * 8)) - 1))
                else:
                    sz = {'b': 1, 'h': 2, 's': 4, 'd': 8}[d0[0]]
                    VREG[int(d0[1:])] = VREG[int(d1[1:])] & ((1 << (sz * 8)) - 1)
        elif mn in ('ldxr', 'ldaxr', 'ldxrh', 'ldaxrh', 'ldxrb', 'ldaxrb', 'ldar', 'ldarh', 'ldarb'):
            a = maddr(ops[1])
            sz = 8 if rnm(ops[0].reg)[0] == 'x' else 4
            if mn.endswith('h'): sz = 2
            elif mn.endswith('b'): sz = 1
            set_reg(rnm(ops[0].reg), int.from_bytes(mem.read(a, sz), 'little'))
        elif mn in ('stxr', 'stlxr', 'stxrh', 'stlxrh', 'stxrb', 'stlxrb'):
            a = maddr(ops[2])
            rn = rnm(ops[1].reg)
            sz = 8 if rn[0] == 'x' else 4
            if mn.endswith('h'): sz = 2
            elif mn.endswith('b'): sz = 1
            mem.write(a, (get_reg(rn) & ((1 << (sz * 8)) - 1)).to_bytes(sz, 'little'))
            set_reg(rnm(ops[0].reg), 0)
        elif mn in ('stlr', 'stlrh', 'stlrb'):
            a = maddr(ops[1])
            rn = rnm(ops[0].reg)
            sz = 8 if rn[0] == 'x' else 4
            if mn.endswith('h'): sz = 2
            elif mn.endswith('b'): sz = 1
            mem.write(a, (get_reg(rn) & ((1 << (sz * 8)) - 1)).to_bytes(sz, 'little'))
        elif mn in ('ldxp', 'ldaxp'):
            a = maddr(ops[2])
            set_reg(rnm(ops[0].reg), int.from_bytes(mem.read(a, 8), 'little'))
            set_reg(rnm(ops[1].reg), int.from_bytes(mem.read(a + 8, 8), 'little'))
        elif mn in ('stxp', 'stlxp'):
            a = maddr(ops[3])
            mem.write(a, get_reg(rnm(ops[1].reg)).to_bytes(8, 'little'))
            mem.write(a + 8, get_reg(rnm(ops[2].reg)).to_bytes(8, 'little'))
            set_reg(rnm(ops[0].reg), 0)
        elif mn in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsh', 'ldrsb',
                    'ldur', 'ldurb', 'ldurh', 'ldursw', 'ldursh', 'ldursb'):
            o = ops[1]
            if o.type == ARM64_OP_IMM:
                a = o.imm; post = None
            else:
                a = maddr(o)
                post = ops[2].imm if len(ops) > 2 else None
                if i.writeback and post is None:
                    set_reg(rnm(o.mem.base), a)
            dst0 = rnm(ops[0].reg)
            if dst0[0] in 'bhsdq':
                vsz = {'b': 1, 'h': 2, 's': 4, 'd': 8, 'q': 16}[dst0[0]]
                VREG[int(dst0[1:])] = int.from_bytes(mem.read(a, vsz), 'little')
                if post is not None:
                    set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
                PC[0] = npc; continue
            sz = 8 if rnm(ops[0].reg)[0] == 'x' else 4
            if mn in ('ldrb', 'ldurb'): sz = 1
            elif mn in ('ldrh', 'ldrsh', 'ldurh', 'ldursh'): sz = 2
            elif mn in ('ldrsw', 'ldrsb', 'ldursw', 'ldursb'): sz = 4 if mn in ('ldrsw', 'ldursw') else 1
            v = int.from_bytes(mem.read(a, sz), 'little')
            dst = rnm(ops[0].reg)
            if mn in ('ldrsw', 'ldursw'): v = sx(v, 32) & MASK64
            elif mn in ('ldrsh', 'ldursh'): v = sx(v, 16) & (MASK64 if dst[0] == 'x' else 0xFFFFFFFF)
            elif mn in ('ldrsb', 'ldursb'): v = sx(v, 8) & (MASK64 if dst[0] == 'x' else 0xFFFFFFFF)
            set_reg(dst, v)
            if post is not None:
                set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
        elif mn in ('str', 'strb', 'strh', 'stur', 'sturb', 'sturh'):
            o = ops[1]
            a = maddr(o)
            post = ops[2].imm if len(ops) > 2 else None
            if i.writeback and post is None:
                set_reg(rnm(o.mem.base), a)
            dst0 = rnm(ops[0].reg)
            if dst0[0] in 'bhsdq':
                vsz = {'b': 1, 'h': 2, 's': 4, 'd': 8, 'q': 16}[dst0[0]]
                mem.write(a, (VREG[int(dst0[1:])] & ((1 << (vsz * 8)) - 1)).to_bytes(vsz, 'little'))
                if post is not None:
                    set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
                PC[0] = npc; continue
            sz = 8 if rnm(ops[0].reg)[0] == 'x' else 4
            if mn in ('strb', 'sturb'): sz = 1
            elif mn in ('strh', 'sturh'): sz = 2
            mem.write(a, (get_reg(rnm(ops[0].reg)) & ((1 << (sz * 8)) - 1)).to_bytes(sz, 'little'))
            if post is not None:
                set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
        elif mn == 'ldpsw':
            o = ops[2]; a = maddr(o)
            post = ops[3].imm if len(ops) > 3 else None
            if i.writeback and post is None:
                set_reg(rnm(o.mem.base), a)
            v1 = sx(int.from_bytes(mem.read(a, 4), 'little'), 32) & MASK64
            v2 = sx(int.from_bytes(mem.read(a + 4, 4), 'little'), 32) & MASK64
            set_reg(rnm(ops[0].reg), v1); set_reg(rnm(ops[1].reg), v2)
            if post is not None:
                set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
        elif mn == 'ldp':
            o = ops[2]; a = maddr(o)
            post = ops[3].imm if len(ops) > 3 else None
            if i.writeback and post is None:
                set_reg(rnm(o.mem.base), a)
            dst0 = rnm(ops[0].reg)
            if dst0[0] in 'bhsdq':
                vsz = {'b': 1, 'h': 2, 's': 4, 'd': 8, 'q': 16}[dst0[0]]
                VREG[int(dst0[1:])] = int.from_bytes(mem.read(a, vsz), 'little')
                VREG[int(dst0[1:]) + 0] = VREG[int(dst0[1:])]
                d2 = rnm(ops[1].reg)
                VREG[int(d2[1:])] = int.from_bytes(mem.read(a + vsz, vsz), 'little')
                if post is not None:
                    set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
                PC[0] = npc; continue
            sz = 8 if rnm(ops[0].reg)[0] == 'x' else 4
            v1 = int.from_bytes(mem.read(a, sz), 'little'); v2 = int.from_bytes(mem.read(a + sz, sz), 'little')
            set_reg(rnm(ops[0].reg), v1); set_reg(rnm(ops[1].reg), v2)
            if post is not None:
                set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
        elif mn == 'stp':
            o = ops[2]; a = maddr(o)
            post = ops[3].imm if len(ops) > 3 else None
            if i.writeback and post is None:
                set_reg(rnm(o.mem.base), a)
            dst0 = rnm(ops[0].reg)
            if dst0[0] in 'bhsdq':
                vsz = {'b': 1, 'h': 2, 's': 4, 'd': 8, 'q': 16}[dst0[0]]
                d2 = rnm(ops[1].reg)
                mem.write(a, (VREG[int(dst0[1:])] & ((1 << (vsz * 8)) - 1)).to_bytes(vsz, 'little'))
                mem.write(a + vsz, (VREG[int(d2[1:])] & ((1 << (vsz * 8)) - 1)).to_bytes(vsz, 'little'))
                if post is not None:
                    set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
                PC[0] = npc; continue
            sz = 8 if rnm(ops[0].reg)[0] == 'x' else 4
            m = (1 << (sz * 8)) - 1
            if DBG and pc == 0x1252b5fc:
                print('  STP a=%#x v0=%#x v1=%#x' % (a, get_reg(rnm(ops[0].reg)), get_reg(rnm(ops[1].reg))))
            mem.write(a, (get_reg(rnm(ops[0].reg)) & m).to_bytes(sz, 'little'))
            mem.write(a + sz, (get_reg(rnm(ops[1].reg)) & m).to_bytes(sz, 'little'))
            if DBG and pc == 0x1252b5fc:
                d0 = (get_reg(rnm(ops[0].reg)) & m).to_bytes(sz, 'little')
                d1 = (get_reg(rnm(ops[1].reg)) & m).to_bytes(sz, 'little')
                print('  STP wrote d0=%s d1=%s id(mem)=%d page=%s' % (d0.hex(), d1.hex(), id(mem), mem.pages.get(0x700fe000)[0xea0:0xeb0].hex()))
            if post is not None:
                set_reg(rnm(o.mem.base), (get_reg(rnm(o.mem.base)) + post) & MASK64)
        else:
            print('UNIMPL %s %s @%#x step=%d' % (mn, i.op_str, pc, step))
            for e in list(ring)[-24:]: print('   %#x %s %s' % e)
            raise RuntimeError('unimpl')
        PC[0] = npc
        if step > maxstep: raise RuntimeError('runaway')


QBUF = 0x1228f000          # free 4KB+ area in region2 (e2 snapshot)
QPAIR, QPTR = 0xe4fff190, 0xe4fff198   # query string cell on r1 stack (e2)

def compute_body(round_idx, verbose=True, query=None):
    """Run one Medusa body round from its snapshot. Returns 225 bytes.
    query: replace the baked-in query string (e2/round1 cell layout assumed)."""
    global mem
    cfg = ROUNDS[round_idx]
    suf = cfg['suf']
    c2 = blob('dump_pe_12a2a000%s_region4.bin' % suf)
    r1 = blob('dump_pe_12a2a000%s_region1.bin' % suf)
    r2 = blob('dump_pe_12a2a000%s_region2.bin' % suf)
    r3 = blob('dump_pe_12a2a000%s_region3.bin' % suf)
    prog = blob('dump_pe_12a2a000%s_prog.bin' % suf)
    ch = blob('dump_pe_12d40000_chain.bin')
    htabd = blob('dump_pe_12a2a000%s_htab.bin' % suf)
    mem = Mem()
    mem.load(C2A, c2[:0x3C0000])
    mem.load(R2A, r2)
    mem.load(R3A, r3)
    mem.load(PROGB, prog)
    mem.load(R1A, r1)
    mem.load(CHA, ch)
    if query is not None:
        _q = query.encode() if isinstance(query, str) else bytes(query)
        mem.write(QBUF, _q + b'\x00')
        mem.write(QPAIR, struct.pack('<II', len(_q) + 1, len(_q)))
        mem.write(QPTR, struct.pack('<Q', QBUF))
    _mp = os.environ.get('MPATCH')
    if _mp:
        for _spec in _mp.split(','):
            _a, _h = _spec.split(':')
            mem.write(int(_a, 0), bytes.fromhex(_h))
            if verbose: print('patched %s %s' % (_a, _h))
    htab = struct.unpack("<1024Q", htabd)
    for _i in range(31): REG[_i] = 0
    for _k, _v in REGS_BASE.items(): REG[_k] = _v
    REG[14] = cfg['ex14']; REG[15] = cfg['ex15']
    SP[0] = STACKA + STACKS - 0x1000
    REG[30] = SENT
    N[0] = Z[0] = C[0] = V[0] = 0
    jni_objs.clear(); next_handle[0] = 0xfffee000
    fdtab.clear(); nextfd[0] = 100; mmap_top[0] = 0x50000000
    del svc_log[:]
    handler_set.clear()
    for _h in htab:
        if R2A <= _h < R2A + len(r2) or C2A <= _h < C2A + 0x3D0000:
            handler_set.add(_h)
    if TRC:
        globals()['trc_f'] = open(os.environ.get('MTRCF', '_trace_py.txt'), 'w', buffering=8192)
        trc_last[0] = None
    hidx0 = struct.unpack("<I", prog[0x28:0x2c])[0]
    pc0 = htab[hidx0]
    if verbose: print('round%d slot0 hidx=%d entry=%#x' % (round_idx, hidx0, pc0))
    PC[0] = pc0
    t0 = time.time()
    global WATCH
    if os.environ.get('MWATCH'):
        _lo, _hi = os.environ['MWATCH'].split('-')
        WATCH = (int(_lo, 0), int(_hi, 0))
    else:
        WATCH = None
    del WLOG[:]
    try:
        steps = run(pc0)
    finally:
        if WATCH is not None:
            with open('_wslot_py.txt', 'w') as _f:
                for _w in WLOG:
                    _f.write('%d %#x %#x %s' % (_w[0], _w[1], _w[2], _w[3].hex()) + chr(10))
    if trc_f is not None: trc_f.close()
    if verbose: print('  done steps=%d time=%.1fs svc=%d' % (steps, time.time() - t0, len(svc_log)))
    return mem.read(cfg['out'], 225)


if __name__ == '__main__':
    rounds = [int(x) for x in sys.argv[1:]] or [0, 1, 2, 3]
    ok = True
    for ri in rounds:
        cfg = ROUNDS[ri]
        gold = bytes.fromhex(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), cfg['gold'])).read().strip())
        out = compute_body(ri)
        m = sum(1 for x, y in zip(out, gold) if x == y)
        stat = 'PASS' if out == gold else 'FAIL'
        if out != gold: ok = False
        print('round%d: %d/%d %s' % (ri, m, len(gold), stat))
        if out != gold:
            print('  got :', out[:40].hex())
            print('  gold:', gold[:40].hex())
        if os.environ.get('MPRINT'):
            print('OUT', out.hex())
    print('ALL PASS' if ok else 'SOME FAIL')
