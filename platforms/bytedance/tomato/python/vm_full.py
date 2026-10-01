# -*- coding: utf-8 -*-
"""vm_full.py — libmetasec_ml VM full interpreter (all ops needed by BC_118570 + E).
Memory: SO image mapped at B, relocs applied (R_AARCH64_RELATIVE -> B+addend).
Entry conventions (from VM entry 0x168324 + wrappers):
  R4 = packed ptr, R5/R6 = wrapper x2/x3 args, R7 = cb sentinel (native-call marker)
  native call: sub50 target==cb -> call f=R4(arg=R5)   (result via arg memory)
  vm exit:     sub50 target==LR sentinel  (or op17 sub30)
"""
import os
import struct
from pathlib import Path

B = 0x775C205000
M64 = 0xFFFFFFFFFFFFFFFF
SO_PATH = Path(os.environ.get(
    "TOMATO_LIBMETASEC",
    str(Path(__file__).with_name("libmetasec_ml_71332.so")),
))
if not SO_PATH.is_file():
    raise FileNotFoundError(
        "Place the private v7.1.3.32 libmetasec_ml_71332.so beside this file "
        "or set TOMATO_LIBMETASEC before importing the diagnostic VM."
    )
SO = SO_PATH.read_bytes()
SEGS = [(0x0, 0x0, 0x348700, 0x348700), (0x348700, 0x34C700, 0x28F10, 0x28F10), (0x371610, 0x379610, 0x57DE8, 0x6A460)]

def v2o(v):
    for fo, va, fs, ms in SEGS:
        if va <= v < va + fs: return fo + (v - va)
    return None

def _load_relocs():
    tags = {}
    for i in range(0x1e0 // 16):
        t, v = struct.unpack_from("<qQ", SO, 0x370d48 + i * 16); tags.setdefault(t, []).append(v)
    roff = v2o(tags[7][0])
    rel = {}
    for i in range(tags[8][0] // 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", SO, roff + i * 24)
        if (r_info & 0xffffffff) == 1027: rel[r_off] = r_add
    return rel

RELOCS = _load_relocs()

def ror64(x, n):
    n &= 63
    return x if n == 0 else ((x >> n) | (x << (64 - n))) & M64

def sx16(v): return v - 0x10000 if v & 0x8000 else v
def sx32(v): return v - 0x100000000 if v & 0x80000000 else v
def sx64(v): return v - (1 << 64) if v >> 63 else v

class Mem:
    def __init__(self):
        self.pages = {}
        # preload image
        for fo, va, fs, ms in SEGS:
            self.wr(B + va, SO[fo:fo + fs])
        for va, add in RELOCS.items():
            o = v2o(va)
            if o is not None:
                self.w64(B + va, (B + add) & M64)
    def _pg(self, a):
        p = self.pages.get(a >> 12)
        if p is None:
            p = bytearray(0x1000); self.pages[a >> 12] = p
        return p
    def rb(self, a): return self._pg(a)[a & 0xFFF]
    def wb(self, a, v): self._pg(a)[a & 0xFFF] = v & 0xFF
    def rd(self, a, n):
        return bytes(self.rb(a + i) for i in range(n))
    def wr(self, a, data):
        for i, b in enumerate(data): self.wb(a + i, b)
    def u64(self, a): return struct.unpack("<Q", self.rd(a, 8))[0]
    def w64(self, a, v): self.wr(a, struct.pack("<Q", v & M64))
    def u32(self, a): return struct.unpack("<I", self.rd(a, 4))[0]
    def w32(self, a, v): self.wr(a, struct.pack("<I", v & 0xFFFFFFFF))

# ---------------- imm perms ----------------
def imm_24(dw):
    return ((dw>>6)&0x1F) | (((dw>>16)&0x1F)<<5) | (((dw>>11)&0x1F)<<10) | (((dw>>26)&1)<<15)
def imm_26(dw):
    return ((dw>>16)&0x1F) | (((dw>>11)&0x1F)<<5) | (((dw>>6)&0x1F)<<10) | (((dw>>26)&1)<<15)
def imm_59(dw):
    v = ((dw>>21)&0x1F) | (((dw>>11)&1)<<5) | (((dw>>12)&1)<<6) | (((dw>>13)&1)<<7) | (((dw>>14)&1)<<8) | (((dw>>15)&1)<<9)
    v |= (((dw>>26)&0x1F)<<10) | (((dw>>6)&1)<<15)
    return v
def imm_53(dw):
    v = ((dw>>16)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>6)&0x1F)<<10) | (((dw>>21)&1)<<15)
    return v
def imm_55(dw):
    return ((dw>>6)&0x1F) | (((dw>>21)&0x1F)<<5) | (((dw>>16)&0x1F)<<10) | (((dw>>26)&1)<<15)
def imm_45(dw):
    return ((dw>>16)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>11)&0x1F)<<10) | (((dw>>6)&1)<<15)
def imm_1(dw):
    v = ((dw>>21)&0x1F) | (((dw>>6)&0x1F)<<5) | (((dw>>26)&0x1F)<<10) | (((dw>>16)&1)<<15)
    return v
def imm_15(dw):
    return ((dw>>6)&0x3FF) | (((dw>>26)&0x1F)<<10) | (((dw>>16)&1)<<15)
def imm_16(dw):
    return ((dw>>16)&0x1F) | (((dw>>6)&0x3FF)<<5) | (((dw>>26)&1)<<15)
def imm_20(dw):
    return ((dw>>26)&0x1F) | (((dw>>21)&0x1F)<<5) | (((dw>>16)&0x1F)<<10) | (((dw>>6)&1)<<15)
def imm_22(dw):
    return ((dw>>11)&0x1F) | (((dw>>21)&0x1F)<<5) | (((dw>>6)&0x1F)<<10) | (((dw>>26)&1)<<15)
def imm_40(dw):
    return ((dw>>16)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>6)&0x1F)<<10) | (((dw>>11)&1)<<15)
def imm_43(dw):
    return ((dw>>11)&0x3FF) | (((dw>>26)&0x1F)<<10) | (((dw>>21)&1)<<15)
def imm_48(dw):
    return ((dw>>16)&0x1F) | (((dw>>6)&0x3FF)<<5) | (((dw>>21)&1)<<15)
def imm_52(dw):
    return ((dw>>16)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>6)&0x1F)<<10) | (((dw>>21)&1)<<15)
def imm_9(dw):
    return ((dw>>11)&0x3FF) | (((dw>>26)&0x1F)<<10) | (((dw>>6)&1)<<15)
def imm_3(dw):
    return ((dw>>16)&0x1F) | (((dw>>11)&0x1F)<<5) | (((dw>>21)&0x1F)<<10) | (((dw>>6)&1)<<15)
def jmp_13(dw):
    v = ((dw>>11)&0x1F) | (((dw>>6)&0x1F)<<5) | (((dw>>16)&0x1F)<<10) | (((dw>>26)&0x1F)<<15) | (((dw>>21)&0x1F)<<20) | (((dw>>31)&1)<<25)
    return v

class VMExit(Exception): pass
class NativeCall(Exception):
    def __init__(self, f, arg): self.f, self.arg = f, arg

class VM:
    def __init__(self, mem, entry_va, r4, r5, r6, cb_va, exit_sentinel, log=None, maxsteps=2_000_000):
        self.m = mem; self.R = [0]*32
        self.R[4] = r4; self.R[5] = r5; self.R[6] = r6; self.R[7] = cb_va
        self.cb = cb_va; self.exit = exit_sentinel
        self.pc = B + entry_va
        self.ops = []
        self.snaps = []
        self.base = B + entry_va          # OP13 jump base (entry x0)
        self.steps = 0; self.maxsteps = maxsteps
        self.log = log                    # callable(str) or None
        self.native_hook = None           # callable(vm, f, arg) -> handled?
        self.native_any = False           # optionally treat non-VM CALL targets as native and return
        self.step_hook = None             # optional callable(vm, dw, op, sub)
        self.branch_hook = None           # optional callable(vm, dw) -> absolute next PC
        self.opaque_hook = None            # optional callable(vm, dw, op, sub)
        self.trace = False
        # Native op17/sub26 and sub52 use two hidden VM slots immediately
        # after the 32 traced slots. Keep an abstract copy of those slots.
        self._vm_tmp32 = 0
        self._vm_tmp33 = 0
    def _log(self, s):
        if self.log: self.log(s)
    def fx(self, pc, dw):
        """disasm+effect one instruction (uses current regs/mem)."""
        m = self.m; R = self.R
        op = dw & 0x3F; sub = (dw >> 6) & 0x3F
        def rv(a): return "%x:%x" % (a, R[a] & 0xFFFFFFFFFFFFFFFF)
        try:
            if op == 24:
                bse = ((dw>>27)&0x10)|((dw>>22)&0xF); dst = ((dw>>17)&0x10)|((dw>>27)&0xF)
                imm = sx16(imm_24(dw)); a = (R[bse]+imm) & M64
                return "R%d = [R%d%+d]  ; [%x]=%x" % (dst, bse, imm, a, m.u64(a))
            if op == 26:
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); val = ((dw>>27)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_26(dw)); a = (R[bse]+imm) & M64
                return "[R%d%+d] = R%d ; [%x]=%x" % (bse, imm, val, a, R[val])
            if op == 1:
                bse = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>17)&0xF)|((dw>>7)&0x10)
                imm = sx16(imm_1(dw)); a = (R[bse]+imm) & M64
                return "R%d = s32[R%d%+d] ; [%x]=%x" % (dst, bse, imm, a, m.u32(a))
            if op == 22:
                src = ((dw>>27)&0xF)|((dw>>12)&0x10); bse = ((dw>>17)&0xF)|((dw>>27)&0x10)
                imm = sx16(imm_22(dw)); a = (R[bse]+imm) & M64
                return "u32[R%d%+d] = R%d.w ; [%x]=%x" % (bse, imm, src, a, R[src]&0xFFFFFFFF)
            if op == 16:
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); src = ((dw>>27)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_16(dw)); a = (R[bse]+imm) & M64
                return "u8[R%d%+d] = R%d.b ; [%x]=%x" % (bse, imm, src, a, R[src]&0xFF)
            if op == 40:
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); dst = ((dw>>12)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_40(dw)); a = (R[bse]+imm) & M64
                return "R%d = u8[R%d%+d] ; [%x]=%x" % (dst, bse, imm, a, m.rb(a))
            if op == 15:
                src = ((dw>>22)&0xF)|((dw>>27)&0x10); dst = (dw>>17)&0x1F
                return "R%d = R%d%+d" % (dst, src, sx16(imm_15(dw)))
            if op == 48:
                return "R%d = R%d|%#x" % ((dw>>22)&0x1F, (dw>>27)&0x1F, imm_48(dw))
            if op == 52:
                dst = ((dw>>22)&0xF)|(((dw>>11)&1)<<4)
                return "R%d = %#x" % (dst, sx32(imm_52(dw) << 16) & M64)
            if op == 9:
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); dst = ((dw>>7)&0xF)|((dw>>17)&0x10)
                return "R%d = u32[R%d%+d]" % (dst, bse, sx16(imm_9(dw)))
            if op == 53:
                src = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>22)&0xF)|(((dw>>11)&1)<<4)
                return "R%d = R%d&%#x" % (dst, src, imm_53(dw))
            if op == 59:
                a = ((dw>>17)&0xF)|((dw>>27)&0x10); d = ((dw>>7)&0xF)|((dw>>12)&0x10)
                return "R%d = sext32(R%d)%+d" % (d, a, sx16(imm_59(dw)))
            if op == 55:
                idx = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>27)&0xF)|(((dw>>11)&1)<<4)
                return "R%d = (R%d <%d)" % (dst, idx, sx16(imm_55(dw)))
            if op == 45:
                a = ((dw>>22)&0xF)|((dw>>27)&0x10); b = ((dw>>7)&0xF)|((dw>>21)&0x10)
                if sub == 33:
                    return "if R%d==0 goto %+d ; %x==0 %s" % (a, sx16(imm_45(dw)), R[a], R[a]==0)
                return "if R%d==R%d goto %+d ; %x==%x %s" % (a, b, sx16(imm_45(dw)), R[a], R[b], R[a]==R[b])
            if op == 20:
                a = ((dw>>12)&0xF)|((dw>>27)&0x10); b = (dw>>7)&0x1F
                return "if R%d!=R%d goto %+d ; %x!=%x %s" % (a, b, sx16(imm_20(dw)), R[a], R[b], R[a]!=R[b])
            if op == 43:
                a = ((dw>>7)&0xF)|((dw>>27)&0x10)
                return "if R%d>0 goto %+d ; R%d=%x %s" % (a, sx16(imm_43(dw)), a, R[a], sx64(R[a])>0)
            if op == 13:
                return "goto %d" % jmp_13(dw)
            if op == 4 and sub == 11:
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                return "R%d = (R%d>>%d)&(1<<%d)-1" % (fD, fC, fA, fB+1)
            if op == 4 and sub == 22:
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                return "R%d = bitfield32(R%d, %d, %d)" % (fD, fA, fB, fC + 1)
            if op == 3:
                src = ((dw>>22)&0x10)|((dw>>7)&0xF); bse = (dw>>27)&0x1F
                return "u16[R%d%+d] = R%d" % (bse, sx16(imm_3(dw)), src)
            if op == 33:
                dst = (((dw>>16)&1)<<4) | ((dw>>22)&0xF)
                src = (((dw>>31)&1)<<4) | ((dw>>17)&0xF)
                imm = ((dw>>11)&0x1F)|(((dw>>6)&1)<<5)|(((dw>>7)&1)<<6)|(((dw>>8)&1)<<7)|(((dw>>9)&1)<<8)|(((dw>>10)&1)<<9)|(((dw>>26)&1)<<10)|(((dw>>27)&0xF)<<11)
                return "R%d = (R%d <u %d) ; %x" % (dst, src, imm, R[src])
            if op == 31:
                dst = (((dw>>6)&1)<<4) | ((dw>>12)&0xF)
                bse = (((dw>>31)&1)<<4) | ((dw>>7)&0xF)
                off = (dw>>16)&0x3FFF
                a = (R[bse] + off) & M64
                return "R%d = u16[R%d+%d] ; [%x]=%x" % (dst, bse, off, a, m.rb(a) | (m.rb((a+1)&M64)<<8))
            if op == 61:
                dst = (((dw>>21)&1)<<4) | ((dw>>27)&0xF)
                bse = (((dw>>31)&1)<<4) | ((dw>>22)&0xF)
                off = sx16(imm_26(dw))
                a = (R[bse] + off) & M64
                return "R%d = s8[R%d%+d] ; [%x]=%x" % (dst, bse, off, a, m.rb(a))
            if op == 6:
                dst = (((dw>>11)&1)<<4) | ((dw>>17)&0xF)
                src = (((dw>>31)&1)<<4) | ((dw>>12)&0xF)
                mask = ((dw>>6)&1) | (((dw>>7)&0xF)<<1) | (((dw>>21)&0x3FF)<<5) | (((dw>>16)&1)<<15)
                return "R%d = R%d^%#x ; %x" % (dst, src, mask, R[src])
            if op == 29 and sub == 34:
                a = ((dw>>27)&0x10) | ((dw>>7)&0xF)
                imm = sx16(((dw>>11)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>21)&1)<<10) | (((dw>>22)&0xF)<<11) | (((dw>>16)&1)<<15))
                return "if R%d<=0 goto %+d ; R%d=%x %s" % (a, imm, a, R[a], sx64(R[a]) <= 0)
            if op == 17:
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                if sub == 0: return "R%d = sext32((i32)R%d >>a %d) ; %x" % (fA, fB, fD, R[fB])
                if sub == 3: return "R%d = sext32((u32)R%d << %d) ; %x" % (fB, fD, fC, R[fD])
                if sub == 7:
                    if (dw>>27)&1:
                        dst = ((dw>>12)&1)|(((dw>>28)&0xF)<<1)
                        return "R%d = sext32(ror32((u32)R%d,%d)) ; %x" % (dst, fB, fC&31, R[fB])
                    imm5 = ((dw>>22)&1)|(((dw>>28)&0xF)<<1)
                    return "R%d = sext32((u32)R%d >>l %d) ; %x" % (fB, fA, imm5, R[fA])
                if sub == 10: return "R%d = R%d & R%d ; %x&%x" % (fA, fC, fD, R[fC], R[fD])
                if sub == 16: return "R%d = R%d - R%d ; %x-%x" % (fA, fB, fD, R[fB], R[fD])
                if sub == 18:
                    if fA & 1:
                        src = (fA & 30) | (fB & 1)
                        return "R%d = sext32(ror32(R%d, R%d & 31))" % (fD, src, fC)
                    src = (fA & 30) | (fD & 1)
                    return "R%d = sext32((u32)R%d >> (R%d & 31))" % (fC, src, fB)
                if sub == 46: return "R%d = sext32((u32)R%d - (u32)R%d) ; %x-%x" % (fC, fB, fA, R[fB]&0xFFFFFFFF, R[fA]&0xFFFFFFFF)
                if sub == 26:
                    return "u32div [R28+8*%d] / [R28+8*%d] -> [R17], *[R29-0x18]" % (
                        fB, fD
                    )
                if sub == 48: return "R%d = ~(R%d | R%d)" % (fC, fA, fD)
                if sub == 51: return "R%d = sext32((u32)R%d + (u32)R%d) ; %x+%x" % (fA, fD, fC, R[fD]&0xFFFFFFFF, R[fC]&0xFFFFFFFF)
                if sub == 54: return "R%d = (R%d <u R%d) ; %x<%x" % (fB, fA, fD, R[fA], R[fD])
                if sub == 13: return "nop"
                if sub == 14: return "R%d = R%d + R%d ; %x+%x" % (fB, fC, fA, R[fC], R[fA])
                if sub == 23: return "R%d = R%d << %d" % (fA, fB, fC)
                if sub == 29: return "R%d = R%d ^ R%d" % (fD, fB, fA)
                if sub == 30: return "EXIT"
                if sub == 32: return "if R%d: R%d = R%d ; %x" % (fB, fD, fC, R[fB])
                if sub == 34: return "R%d = sext32((u32)R%d << R%d) ; %x << %x" % (fA, fD, fC, R[fD]&0xFFFFFFFF, R[fC]&0xFFFFFFFF)
                if sub == 33:
                    if (dw>>27)&1: return "R%d = ror(R%d,%d)" % (fA, fC, fB)
                    src = ((dw>>22)&1)|(((dw>>28)&0xF)<<1)
                    return "R%d = R%d>>%d" % (fA, src, fB)
                if sub == 38:
                    if (dw>>27)&1:
                        dst = ((dw>>17)&1)|(((dw>>28)&0xF)<<1)
                        return "R%d = ror(R%d,%d)" % (dst, fC, 32+fA)
                    return "R%d = R%d>>%d" % (fA, fC, 32+fB)
                if sub == 43: return "R%d = (R%d <s R%d) ; %x<%x" % (fA, fC, fD, R[fC], R[fD])
                if sub == 44: return "R%d = R%d | R%d ; %x|%x" % (fA, fD, fC, R[fD], R[fC])
                if sub == 45:
                    src = (fA & 30) | (fB & 1)
                    return "R%d = R%d >> (R%d & 63) ; %x >> %x" % (
                        fD, src, fC, R[src], R[fC]
                    )
                if sub == 58:
                    return "R%d = R%d << (R%d & 63)" % (fC, fB, fA)
                if sub == 50:
                    return "CALL R%d (lnk R%d) ; target=%x" % (fC, fB, R[fC])
                return "op17 sub%d ?" % sub
            return "op%d sub%d?" % (op, sub)
        except Exception as e:
            return "fx-exc %r" % e

    def run(self):
        m = self.m
        while True:
            self.steps += 1
            if self.steps > self.maxsteps: raise RuntimeError("step limit @%x" % self.pc)
            dw = m.u32(self.pc)
            op = dw & 0x3F; sub = (dw >> 6) & 0x3F
            self.ops.append((op, sub))
            if self.step_hook is not None:
                self.step_hook(self, dw, op, sub)
            npc = (self.pc + 4) & M64
            fx = self.fx(self.pc, dw) if self.trace else ""
            if self.trace: self._log("%6d pc=%#x %s" % (self.steps, self.pc, fx))
            if op == 24:        # LOAD64
                bse = ((dw>>27)&0x10)|((dw>>22)&0xF); dst = ((dw>>17)&0x10)|((dw>>27)&0xF)
                imm = sx16(imm_24(dw))
                self.R[dst] = m.u64((self.R[bse] + imm) & M64)
            elif op == 26:      # STORE64
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); val = ((dw>>27)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_26(dw))
                m.w64((self.R[bse] + imm) & M64, self.R[val])
            elif op == 1:       # LOAD32S
                bse = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>17)&0xF)|((dw>>7)&0x10)
                imm = sx16(imm_1(dw))
                self.R[dst] = sx32(m.u32((self.R[bse] + imm) & M64)) & M64
            elif op == 22:      # STORE32
                src = ((dw>>27)&0xF)|((dw>>12)&0x10); bse = ((dw>>17)&0xF)|((dw>>27)&0x10)
                imm = sx16(imm_22(dw))
                m.w32((self.R[bse] + imm) & M64, self.R[src] & 0xFFFFFFFF)
            elif op == 16:      # STORE8
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); src = ((dw>>27)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_16(dw))
                m.wb((self.R[bse] + imm) & M64, self.R[src] & 0xFF)
            elif op == 40:      # LOAD8U
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10); dst = ((dw>>12)&0xF)|((dw>>17)&0x10)
                imm = sx16(imm_40(dw))
                self.R[dst] = m.rb((self.R[bse] + imm) & M64)
            elif op == 36:      # MOVZ-like zeroing form observed in VM9 trace
                # The only captured encodings are 0x4001a4 (R3=0) and
                # 0x4003a4 (R7=0); bits 7..11 select the destination.
                dst = (dw >> 7) & 0x1F
                self.R[dst] = 0
            elif op == 57:      # opaque host-side handler; no virtual-register delta in trace
                # VM9 captures show both observed forms (0x20400039 and
                # 0x40400039) leaving all 32 virtual registers unchanged.
                pass
            elif op == 47:      # LWL: merge left part of an unaligned 32-bit load
                bse = ((dw >> 12) & 15) | ((dw >> 27) & 16)
                dst = ((dw >> 22) & 15) | ((dw >> 7) & 16)
                imm = ((dw >> 16) & 31) | (((dw >> 6) & 31) << 5) | (((dw >> 26) & 31) << 10) | (((dw >> 21) & 1) << 15)
                addr = (self.R[bse] + sx16(imm)) & M64
                offset = addr & 3
                value = m.u32(addr & ~3)
                result = (value << (24 - offset * 8)) | (self.R[dst] & (0xFFFFFF >> (offset * 8)))
                self.R[dst] = sx32(result & 0xFFFFFFFF) & M64
            elif op == 63:      # LWR: merge right part of an unaligned 32-bit load
                bse = (dw >> 27) & 31
                dst = (dw >> 22) & 31
                imm = ((dw >> 6) & 31) | (((dw >> 16) & 31) << 5) | (((dw >> 11) & 31) << 10) | (((dw >> 21) & 1) << 15)
                addr = (self.R[bse] + sx16(imm)) & M64
                shift = (addr & 3) * 8
                value = m.u32(addr & ~3)
                result = value if not shift else (value >> shift) | (self.R[dst] & (0xFFFFFFFF << (32 - shift)))
                self.R[dst] = sx32(result & 0xFFFFFFFF) & M64
            elif op == 4 and sub == 34:
                a, b, c, d = ((dw >> shift) & 31 for shift in (12, 17, 22, 27))
                if a == 2:      # REV16 W, then SXTW
                    value = self.R[b] & 0xFFFFFFFF
                    self.R[d] = sx32(((value & 0x00FF00FF) << 8) | ((value & 0xFF00FF00) >> 8)) & M64
                elif a == 16:   # SXTB
                    value = self.R[c] & 0xFF
                    self.R[d] = (value - 0x100 if value & 0x80 else value) & M64
                elif a == 24:   # SXTH
                    self.R[c] = sx16(self.R[d] & 0xFFFF) & M64
                else:
                    raise ValueError("op4 sub34 variant %d @%#x" % (a, self.pc))
            elif op == 15:      # ADDi
                src = ((dw>>22)&0xF)|((dw>>27)&0x10); dst = (dw>>17)&0x1F
                self.R[dst] = (self.R[src] + sx16(imm_15(dw))) & M64
            elif op == 48:      # ORi
                src = (dw>>27)&0x1F; dst = (dw>>22)&0x1F
                self.R[dst] = self.R[src] | imm_48(dw)
            elif op == 52:      # MOVhi
                # Register field is R[22:25] plus the high bit at bit 11.
                # Bit 27 belongs to the immediate encoding.
                dst = ((dw>>22)&0xF)|(((dw>>11)&1)<<4)
                self.R[dst] = sx32(imm_52(dw) << 16) & M64
            elif op == 9:       # LOAD32U with OP9's signed displacement
                bse = ((dw>>22)&0xF)|((dw>>27)&0x10)
                dst = ((dw>>7)&0xF)|((dw>>17)&0x10)
                self.R[dst] = m.u32((self.R[bse] + sx16(imm_9(dw))) & M64)
            elif op == 53:      # ANDi
                src = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>22)&0xF)|(((dw>>11)&1)<<4)
                self.R[dst] = self.R[src] & imm_53(dw)
            elif op == 59:      # MOVsxt (sext32(src) + imm)
                a = ((dw>>17)&0xF)|((dw>>27)&0x10); d = ((dw>>7)&0xF)|((dw>>12)&0x10)
                self.R[d] = (sx32(self.R[a] & 0xFFFFFFFF) + sx16(imm_59(dw))) & M64
            elif op == 55:      # SLTi
                idx = ((dw>>12)&0xF)|((dw>>27)&0x10); dst = ((dw>>27)&0xF)|(((dw>>11)&1)<<4)
                self.R[dst] = 1 if sx64(self.R[idx]) < sx16(imm_55(dw)) else 0
            elif op == 45:      # conditional branch family
                a = ((dw>>22)&0xF)|((dw>>27)&0x10); b = ((dw>>7)&0xF)|((dw>>21)&0x10)
                # VM9 has several conditional forms sharing OP45's field
                # layout. Sub=0 is a signed nonpositive test; sub=33 is an
                # exact zero test; sub=53 is !=. Other forms remain ==.
                if sub == 0:
                    taken = sx64(self.R[a]) <= 0
                elif sub == 33:
                    taken = self.R[a] == 0
                elif sub == 53:
                    taken = self.R[a] != self.R[b]
                else:
                    taken = self.R[a] == self.R[b]
                if taken: npc = (self.pc + 4 + 4*sx16(imm_45(dw))) & M64
            elif op == 20:      # BNE
                a = ((dw>>12)&0xF)|((dw>>27)&0x10); b = (dw>>7)&0x1F
                if self.R[a] != self.R[b]: npc = (self.pc + 4 + 4*sx16(imm_20(dw))) & M64
            elif op == 43:      # BGT (signed reg > 0)
                a = ((dw>>7)&0xF)|((dw>>27)&0x10)
                if sx64(self.R[a]) > 0: npc = (self.pc + 4 + 4*sx16(imm_43(dw))) & M64
            elif op == 13:      # JMP (abs idx from entry base)
                npc = (self.base + 4*jmp_13(dw)) & M64
                if self.branch_hook is not None:
                    target = self.branch_hook(self, dw)
                    if target is not None:
                        npc = target & M64
            elif op == 4 and sub == 11:   # bitfield extract
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                mask = M64 if fB == 63 else (1 << (fB + 1)) - 1
                self.R[fD] = (self.R[fC] >> fA) & mask
            elif op == 4 and sub == 22:   # 32-bit bitfield extract, then SXTW
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                value = self.R[fA] & 0xFFFFFFFF
                result = value if fC == 31 else (value >> fB) & ((1 << (fC + 1)) - 1)
                self.R[fD] = sx32(result) & M64
            elif op == 3:       # STORE16
                src = ((dw>>22)&0x10)|((dw>>7)&0xF); bse = (dw>>27)&0x1F
                addr = (self.R[bse] + sx16(imm_3(dw))) & M64
                m.wr(addr, struct.pack("<H", self.R[src] & 0xFFFF))
            elif op == 33:      # SLTIU (unsigned R[src] < imm)
                dst = (((dw>>16)&1)<<4) | ((dw>>22)&0xF)
                src = (((dw>>31)&1)<<4) | ((dw>>17)&0xF)
                imm = ((dw>>11)&0x1F)|(((dw>>6)&1)<<5)|(((dw>>7)&1)<<6)|(((dw>>8)&1)<<7)|(((dw>>9)&1)<<8)|(((dw>>10)&1)<<9)|(((dw>>26)&1)<<10)|(((dw>>27)&0xF)<<11)
                self.R[dst] = 1 if self.R[src] < imm else 0
            elif op == 31:      # LOAD16U
                dst = (((dw>>6)&1)<<4) | ((dw>>12)&0xF)
                bse = (((dw>>31)&1)<<4) | ((dw>>7)&0xF)
                off = (dw>>16)&0x3FFF
                a = (self.R[bse] + off) & M64
                self.R[dst] = m.rb(a) | (m.rb((a+1)&M64) << 8)
            elif op == 61:      # LOAD8S variant
                dst = (((dw>>21)&1)<<4) | ((dw>>27)&0xF)
                bse = (((dw>>31)&1)<<4) | ((dw>>22)&0xF)
                off = sx16(imm_26(dw))
                v = m.rb((self.R[bse] + off) & M64)
                self.R[dst] = (v - 0x100 if v & 0x80 else v) & M64
            elif op == 6:       # XORi (imm mask; only instance has mask=1)
                dst = (((dw>>11)&1)<<4) | ((dw>>17)&0xF)
                src = (((dw>>31)&1)<<4) | ((dw>>12)&0xF)
                mask = ((dw>>6)&1) | (((dw>>7)&0xF)<<1) | (((dw>>21)&0x3FF)<<5) | (((dw>>16)&1)<<15)
                self.R[dst] = (self.R[src] ^ mask) & M64
            elif op == 29:   # BLEZ; the six bits called "sub" are operand bits
                a = ((dw>>27)&0x10) | ((dw>>7)&0xF)
                imm = sx16(((dw>>11)&0x1F) | (((dw>>26)&0x1F)<<5) | (((dw>>21)&1)<<10) | (((dw>>22)&0xF)<<11) | (((dw>>16)&1)<<15))
                if sx64(self.R[a]) <= 0: npc = (self.pc + 4 + 4*imm) & M64
            elif op == 17:
                fA=(dw>>12)&0x1F; fB=(dw>>17)&0x1F; fC=(dw>>22)&0x1F; fD=(dw>>27)&0x1F
                if sub == 0:
                    self.R[fA] = sx32((sx32(self.R[fB] & 0xFFFFFFFF) >> fD)) & M64
                elif sub == 3:
                    self.R[fB] = sx32(((self.R[fD] & 0xFFFFFFFF) << (fC & 31)) & 0xFFFFFFFF) & M64
                elif sub == 7:
                    if (dw>>27)&1:
                        dst = ((dw>>12)&1)|(((dw>>28)&0xF)<<1)
                        v = self.R[fB] & 0xFFFFFFFF; n = fC & 31
                        r = ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF if n else v
                        self.R[dst] = sx32(r) & M64
                    else:
                        imm5 = ((dw>>22)&1)|(((dw>>28)&0xF)<<1)
                        self.R[fB] = sx32((self.R[fA] & 0xFFFFFFFF) >> imm5) & M64
                elif sub == 10: self.R[fA] = self.R[fC] & self.R[fD]
                elif sub == 13: pass
                elif sub == 14: self.R[fB] = (self.R[fC] + self.R[fA]) & M64
                elif sub == 16: self.R[fA] = (self.R[fB] - self.R[fD]) & M64
                elif sub == 18:
                    # ARM64 handlers 0x169df0 / 0x169ed8: bit 12 selects
                    # LSRV / RORV. Both operate on W registers then SXTW.
                    if fA & 1:
                        src = (fA & 30) | (fB & 1)
                        value = self.R[src] & 0xFFFFFFFF
                        count = self.R[fC] & 31
                        result = ((value >> count) | (value << ((32 - count) & 31))) & 0xFFFFFFFF
                        self.R[fD] = sx32(result) & M64
                    else:
                        src = (fA & 30) | (fD & 1)
                        self.R[fC] = sx32((self.R[src] & 0xFFFFFFFF) >> (self.R[fB] & 31)) & M64
                elif sub == 23: self.R[fA] = (self.R[fB] << fC) & M64
                elif sub == 29: self.R[fD] = self.R[fB] ^ self.R[fA]
                elif sub == 30: raise VMExit()
                elif sub == 32:   # CMOV if R[c]!=0: R[d]=R[s]
                    c = fB; s = fC; d = fD
                    if self.R[c] != 0: self.R[d] = self.R[s]
                elif sub == 34:
                    # 32-bit logical left shift followed by sign extension.
                    self.R[fA] = sx32(((self.R[fD] & 0xFFFFFFFF) << (self.R[fC] & 31)) & 0xFFFFFFFF) & M64
                elif sub == 33:
                    if (dw>>27)&1: self.R[fA] = ror64(self.R[fC], fB)
                    else:
                        src = ((dw>>22)&1)|(((dw>>28)&0xF)<<1)
                        self.R[fA] = self.R[src] >> fB
                elif sub == 38:
                    if (dw>>27)&1:
                        dst = ((dw>>17)&1)|(((dw>>28)&0xF)<<1)
                        self.R[dst] = ror64(self.R[fC], 32 + fA)
                    else:
                        self.R[fA] = self.R[fC] >> (32 + fB)
                elif sub == 43:   # SLT signed
                    self.R[fA] = 1 if sx64(self.R[fC]) < sx64(self.R[fD]) else 0
                elif sub == 46:
                    self.R[fC] = sx32(((self.R[fB] & 0xFFFFFFFF) - (self.R[fA] & 0xFFFFFFFF)) & 0xFFFFFFFF) & M64
                elif sub == 48:
                    self.R[fC] = (~(self.R[fA] | self.R[fD])) & M64
                elif sub == 51:
                    self.R[fA] = sx32(((self.R[fD] & 0xFFFFFFFF) + (self.R[fC] & 0xFFFFFFFF)) & 0xFFFFFFFF) & M64
                elif sub == 54:
                    self.R[fB] = 1 if self.R[fA] < self.R[fD] else 0
                elif sub == 26:   # 32-bit unsigned divmod (native handler 0x16b97c)
                    # The native handler reads 32-bit values from the VM slot
                    # array at x28 and writes sign-extended quotient/remainder
                    # into hidden slots 32 and 33.  R[0:32] is the abstract
                    # view of that same array in this runner.
                    lhs = self.R[fB] & 0xFFFFFFFF
                    rhs = self.R[fD] & 0xFFFFFFFF
                    if rhs == 0:
                        raise ZeroDivisionError("VM op17/sub26 unsigned divide by zero")
                    quotient, remainder = divmod(lhs, rhs)
                    self._vm_tmp32 = sx32(quotient) & M64
                    self._vm_tmp33 = sx32(remainder) & M64
                    reg_base = self.R[28] & M64
                    m.w64((reg_base + 0x100) & M64, self._vm_tmp32)
                    m.w64((reg_base + 0x108) & M64, self._vm_tmp33)
                elif sub == 52:   # commit the divmod remainder into a VM slot
                    # The normal arm64 path copies the temporary remainder
                    # held at *[x29-0x18] into slot fB.  The alternate opaque
                    # path additionally scrambles the temporary after the
                    # copy; that value is consumed only by later native state,
                    # so preserve the observable slot update here.
                    value = self._vm_tmp33
                    dst = fB
                    self.R[dst] = value
                    m.w64((self.R[28] + 8 * dst) & M64, value)
                elif sub == 12:   # logical left shift by 32 + fA
                    # Native handler 0x16882c loads slot fD and writes the
                    # 64-bit shifted value to slot fC.
                    self.R[fC] = (self.R[fD] << (32 + fA)) & M64
                elif sub == 44:   # OR
                    self.R[fA] = self.R[fD] | self.R[fC]
                elif sub == 45:   # variable logical right shift (LSRV)
                    # Native handler 0x169c3c selects the source register
                    # from fA[4:1] plus fB[0], uses the value in R[fC] as a
                    # 64-bit shift count, and stores the result in R[fD].
                    src = (fA & 30) | (fB & 1)
                    self.R[fD] = (self.R[src] >> (self.R[fC] & 63)) & M64
                elif sub == 58:   # variable logical left shift (LSLV)
                    self.R[fC] = (self.R[fB] << (self.R[fA] & 63)) & M64
                elif sub == 50:   # CALL
                    lnk = fB; tgt = self.R[fC]
                    self.R[lnk] = (self.pc + 4) & M64
                    if tgt == self.cb:
                        f = self.R[4]; arg = self.R[5]
                        self._log("NATIVE CALL @step %d pc=%#x f=%#x arg=%#x" % (self.steps, self.pc, f, arg))
                        if self.native_hook: self.native_hook(self, f, arg)
                        else: raise NativeCall(f, arg)
                    elif tgt == self.exit:
                        self._log("VM EXIT (call sentinel) @step %d" % self.steps)
                        raise VMExit()
                    elif self.native_any and self.native_hook is not None:
                        # Some captured VM paths call a native function directly instead
                        # of first branching through the callback sentinel.  Native code
                        # returns to the next VM instruction; the hook receives the
                        # function pointer in R4 and its packed argument in R5.
                        self._log("DIRECT NATIVE CALL @step %d pc=%#x f=%#x arg=%#x" % (self.steps, self.pc, self.R[4], self.R[5]))
                        self.native_hook(self, self.R[4], self.R[5])
                        npc = (self.pc + 4) & M64
                    else:
                        npc = tgt
                else:
                    raise ValueError("op17 sub %d @%#x" % (sub, self.pc))
            elif op == 0:
                raise ValueError("op0 (padding?) @%#x dw=%08x" % (self.pc, dw))
            elif op == 4 and sub != 11:
                if sub == 3:       # BFI Wdst, Wsrc, #lsb, #width
                    # OP4/sub3 is the ARM64 bit-field-insert family.  The
                    # four five-bit fields are encoded as lsb=fA, dst=fB,
                    # src=fC, and the inclusive high bit fD; the native
                    # handler operates on W registers and sign-extends the
                    # resulting 32-bit value back into the VM slot.
                    fA = (dw >> 12) & 0x1F
                    fB = (dw >> 17) & 0x1F
                    fC = (dw >> 22) & 0x1F
                    fD = (dw >> 27) & 0x1F
                    width = fD - fA + 1
                    if width <= 0:
                        raise ValueError("op4/sub3 invalid width %d @%#x" % (width, self.pc))
                    field_mask = ((1 << width) - 1) << fA if width < 32 else 0xFFFFFFFF
                    src = self.R[fC] & 0xFFFFFFFF
                    dst = self.R[fB] & 0xFFFFFFFF
                    result = (dst & ~field_mask) | ((src << fA) & field_mask)
                    self.R[fB] = sx32(result & 0xFFFFFFFF) & M64
                elif self.opaque_hook is not None:
                    self.opaque_hook(self, dw, op, sub)
                else:
                    raise ValueError("op %d @%#x dw=%08x" % (op, self.pc, dw))
            else:
                raise ValueError("op %d @%#x dw=%08x" % (op, self.pc, dw))
            self.pc = npc
            if self.trace: self.snaps.append(list(self.R))
