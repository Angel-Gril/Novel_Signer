# -*- coding: utf-8 -*-
"""Helios VM (libmetasec_ml_71332.so @0x118F50) - pure Python translation.
Semantics reverse-engineered from ARM64 handlers + validated vs Unicorn trace3.json
(489 steps x 32 regs bit-exact) and cross-validated vs Unicorn on 200 random inputs.
"""
import struct

M64 = 0xFFFFFFFFFFFFFFFF

def ror64(x, n):
    n &= 63
    if n == 0: return x & M64
    return ((x >> n) | (x << (64 - n))) & M64

def sx16(v): return v - 0x10000 if v & 0x8000 else v
def sx32(v): return v - 0x100000000 if v & 0x80000000 else v

class Mem:
    def __init__(self): self.d = {}
    def wr(self, a, data):
        for i, b in enumerate(data): self.d[a + i] = b
    def rd(self, a, n):
        return bytes(self.d.get(a + i, 0) for i in range(n))
    def u64(self, a): return struct.unpack("<Q", self.rd(a, 8))[0]
    def w64(self, a, v): self.wr(a, struct.pack("<Q", v & M64))

# ---- bytecode program: 64 dwords at SO+0x118F50 (embedded, self-contained) ----
BC = [
    0x11000418, 0x19000018, 0x09000218, 0x30400218, 0x20400018, 0x000002bb, 0x1ddf5035, 0x082070b7,
    0x004b002d, 0x09901851, 0x01021391, 0x31fe02c4, 0x00cc65d1, 0x018c3391, 0x31800018, 0x300c1751,
    0x0903d991, 0x200c1751, 0x002a02bb, 0x0000300d, 0x3088001a, 0x2080001a, 0x07c00791, 0x00000000,
    0x03307bec, 0x9b83bd86, 0x4358d4f2, 0x7f2353a5, 0x561a4bb4, 0xd000993d, 0xd37c6983, 0x72784a5e,
    0x77968400, 0x0b15d49d, 0xbc6ddbf8, 0xe961d7b6, 0x2b04b53e, 0x5d5bbbba, 0xeebae1af, 0x1621dae3,
    0x1f4b9206, 0x31177b0e, 0x8ca7bb11, 0x6da0c0fe, 0x26f8856c, 0x6a0e29e1, 0x2002f3d4, 0xf27fc5aa,
    0x000000fd, 0x00000000, 0x00000000, 0x00000000, 0x62081ede, 0xa9b18ce4, 0x7468b0c1, 0x1e15609d,
    0x357c7fd0, 0xb366ac0b, 0xb14d51b6, 0x4a48726a, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]
# logical program = first 23 dwords (rest of the 64-dword page is other data/unused)

def imm_perm_24(dw):
    # OP24 imm16: bits[0:5]=dw[6:11], bits[5:10]=dw[16:21], bits[10:15]=dw[11:16], bit15=dw[26]
    v = ((dw >> 6) & 0x1F)
    v |= ((dw >> 16) & 0x1F) << 5
    v |= ((dw >> 11) & 0x1F) << 10
    v |= ((dw >> 26) & 1) << 15
    return v

def imm_perm_59(dw):
    # OP59 imm16: [0:5]=dw[21:26], 5=dw11,6=dw12,7=dw13,8=dw14,9=dw15,
    #             10=dw26,11=dw27,12=dw28,13=dw29,14=dw30,15=dw6
    v = ((dw >> 21) & 0x1F)
    v |= ((dw >> 11) & 1) << 5
    v |= ((dw >> 12) & 1) << 6
    v |= ((dw >> 13) & 1) << 7
    v |= ((dw >> 14) & 1) << 8
    v |= ((dw >> 15) & 1) << 9
    v |= ((dw >> 26) & 1) << 10
    v |= ((dw >> 27) & 1) << 11
    v |= ((dw >> 28) & 1) << 12
    v |= ((dw >> 29) & 1) << 13
    v |= ((dw >> 30) & 1) << 14
    v |= ((dw >> 6) & 1) << 15
    return v

def imm_perm_26(dw):
    # OP26 imm16: [0:5]=dw[16:21], 5=dw11,6=dw12,7=dw13,8=dw14,9=dw15,
    #             10=dw6,11=dw7,12=dw8,13=dw9,14=dw10,15=dw26
    v = ((dw >> 16) & 0x1F)
    v |= ((dw >> 11) & 1) << 5
    v |= ((dw >> 12) & 1) << 6
    v |= ((dw >> 13) & 1) << 7
    v |= ((dw >> 14) & 1) << 8
    v |= ((dw >> 15) & 1) << 9
    v |= ((dw >> 6) & 1) << 10
    v |= ((dw >> 7) & 1) << 11
    v |= ((dw >> 8) & 1) << 12
    v |= ((dw >> 9) & 1) << 13
    v |= ((dw >> 10) & 1) << 14
    v |= ((dw >> 26) & 1) << 15
    return v

def imm_perm_53(dw):
    # OP53 imm16: [0:5]=dw[16:21], 5=dw26,6=dw27,7=dw28,8=dw29,9=dw30,
    #             10=dw6,11=dw7,12=dw8,13=dw9,14=dw10,15=dw21
    v = ((dw >> 16) & 0x1F)
    v |= ((dw >> 26) & 1) << 5
    v |= ((dw >> 27) & 1) << 6
    v |= ((dw >> 28) & 1) << 7
    v |= ((dw >> 29) & 1) << 8
    v |= ((dw >> 30) & 1) << 9
    v |= ((dw >> 6) & 1) << 10
    v |= ((dw >> 7) & 1) << 11
    v |= ((dw >> 8) & 1) << 12
    v |= ((dw >> 9) & 1) << 13
    v |= ((dw >> 10) & 1) << 14
    v |= ((dw >> 21) & 1) << 15
    return v

def imm_perm_55(dw):
    # OP55 imm16 (bit-probed via Unicorn): [0:5]=dw[6:11], [5:10]=dw[21:26],
    # [10:15]=dw[16:21], bit15=dw26
    v = ((dw >> 6) & 0x1F)
    v |= ((dw >> 21) & 0x1F) << 5
    v |= ((dw >> 16) & 0x1F) << 10
    v |= ((dw >> 26) & 1) << 15
    return v

def imm_perm_45(dw):
    # OP45 BEQ imm16: [0:5]=dw[16:21], 5=dw26,6=dw27,7=dw28,8=dw29,9=dw30,
    #                 10=dw11,11=dw12,12=dw13,13=dw14,14=dw15,15=dw6
    v = ((dw >> 16) & 0x1F)
    v |= ((dw >> 26) & 0x1F) << 5
    v |= ((dw >> 11) & 0x1F) << 10
    v |= ((dw >> 6) & 1) << 15
    return v

def jmp_target_13(dw):
    # OP13: bits[0:5]=dw[11:16], bit5..9=dw[6..10], bit10..14=dw[16..20],
    #       bit15..19=dw[26..30], bit20..24=dw[21..25], bit25=dw[31]
    v = ((dw >> 11) & 0x1F)
    v |= ((dw >> 6) & 0x1F) << 5
    v |= ((dw >> 16) & 0x1F) << 10
    v |= ((dw >> 26) & 0x1F) << 15
    v |= ((dw >> 21) & 0x1F) << 20
    v |= ((dw >> 31) & 1) << 25
    return v

def run_block(mem, pa, trace=None):
    """Run one 16-byte block. mem: Mem, pa: packed_args addr ([table, input, output]).
    trace: optional list to compare regs against (trace3.json format)."""
    R = [0] * 32
    # dispatcher prologue init (from trace3 item0)
    R[4] = pa
    R[7] = 512649385132   # VM-internal (dispatch ptr) - not read by program
    R[29] = 1880091600    # VM-internal
    pc = 0
    steps = 0
    while True:
        dw = BC[pc]
        op = dw & 0x3F
        sub = (dw >> 6) & 0x3F
        if trace is not None and steps < len(trace):
            t_idx, t_dw, t_op, t_regs, _ = trace[steps]
            assert t_idx == pc, (steps, t_idx, pc)
            assert t_dw == dw, (steps, hex(t_dw), hex(dw))
            for i in range(32):
                if R[i] != t_regs[i]:
                    print("DIVERGE step %d bc[%d] dw=%08x: R[%d] mine=%016x trace=%016x" %
                          (steps, pc, dw, i, R[i], t_regs[i]))
                    return False
        # execute
        npc = pc + 1
        if op == 24:  # LOAD64
            base = ((dw >> 27) & 0x10) | ((dw >> 22) & 0xF)
            dst = ((dw >> 17) & 0x10) | ((dw >> 27) & 0xF)
            imm = sx16(imm_perm_24(dw))
            R[dst] = mem.u64((R[base] + imm) & M64)
        elif op == 26:  # STORE64
            base = ((dw >> 22) & 0xF) | ((dw >> 27) & 0x10)
            val = ((dw >> 27) & 0xF) | ((dw >> 21) & 0x10)
            imm = sx16(imm_perm_26(dw))
            mem.w64((R[base] + imm) & M64, R[val])
        elif op == 59:  # ADD sext32(reg[idxA]) + sext16(imm)
            idxA = ((dw >> 17) & 0xF) | ((dw >> 27) & 0x10)
            idxB = ((dw >> 7) & 0xF) | ((dw >> 12) & 0x10)
            imm = sx16(imm_perm_59(dw))
            R[idxB] = (sx32(R[idxA] & 0xFFFFFFFF) + imm) & M64
        elif op == 53:  # AND imm16 (result <= 0xFFFF)
            idxA = ((dw >> 12) & 0xF) | ((dw >> 27) & 0x10)
            idxB = ((dw >> 22) & 0xF) | ((dw >> 11) & 0x10)
            R[idxB] = R[idxA] & imm_perm_53(dw)
        elif op == 55:  # SETLT: reg[dst] = (reg[idx] <s sext16(imm)) ? 1 : 0
            idx = ((dw >> 12) & 0xF) | ((dw >> 27) & 0x10)
            dst = ((dw >> 27) & 0xF) | ((dw >> 11) & 0x10)
            imm = sx16(imm_perm_55(dw))
            rv = R[idx] - (1 << 64) if R[idx] >> 63 else R[idx]
            R[dst] = 1 if rv < imm else 0
        elif op == 45:  # BEQ regA==regB -> pc = cur+1+imm
            regA = ((dw >> 22) & 0xF) | ((dw >> 27) & 0x10)
            regB = ((dw >> 7) & 0xF) | ((dw >> 21) & 0x10)
            imm = sx16(imm_perm_45(dw))
            if R[regA] == R[regB]:
                npc = pc + 1 + imm
        elif op == 13:  # JMP
            npc = jmp_target_13(dw)
        elif op == 4 and sub == 11:  # UBFX reg[fD] = (reg[fC] >> fA) & ((1<<(fB+1))-1)
            fA = (dw >> 12) & 0x1F; fB = (dw >> 17) & 0x1F
            fC = (dw >> 22) & 0x1F; fD = (dw >> 27) & 0x1F
            mask = M64 if fB == 63 else (1 << (fB + 1)) - 1
            R[fD] = (R[fC] >> fA) & mask
        elif op == 17:
            fA = (dw >> 12) & 0x1F; fB = (dw >> 17) & 0x1F
            fC = (dw >> 22) & 0x1F; fD = (dw >> 27) & 0x1F
            if sub == 14:    # ADD
                R[fB] = (R[fC] + R[fA]) & M64
            elif sub == 23:  # SHL
                R[fA] = (R[fB] << fC) & M64
            elif sub == 29:  # XOR
                R[fD] = R[fB] ^ R[fA]
            elif sub == 33:
                if (dw >> 27) & 1:  # ROR
                    R[fA] = ror64(R[fC], fB)
                else:               # SHR (src = dw[22]|dw[28:32]<<...)
                    src = ((dw >> 22) & 1) | (((dw >> 28) & 0xF) << 1)
                    R[fA] = R[src] >> fB
            elif sub == 38:
                if (dw >> 27) & 1:  # ROR 32+fA
                    dst = ((dw >> 17) & 1) | (((dw >> 28) & 0xF) << 1)
                    R[dst] = ror64(R[fC], 32 + fA)
                else:
                    R[fA] = R[fC] >> (32 + fB)
            elif sub == 30:  # EXIT
                if trace is not None and steps + 1 < len(trace):
                    t2 = trace[steps + 1]
                    for i in range(32):
                        if R[i] != t2[3][i]:
                            print("DIVERGE at exit step %d: R[%d] mine=%016x trace=%016x" %
                                  (steps, i, R[i], t2[3][i]))
                            return False
                return True
            else:
                raise ValueError("op17 sub %d @bc[%d]" % (sub, pc))
        else:
            raise ValueError("op %d @bc[%d]" % (op, pc))
        pc = npc
        steps += 1

def helios_compute(padded: bytes, round_keys: bytes | None = None) -> bytes:
    """Full Helios VM over PKCS7-padded input (multiple of 16).

    ``round_keys`` is the packed 34*u64 table passed as ``packed_args[0]`` by
    the native wrapper.  Older captures used an all-zero table, so the
    historical default remains zero-filled; newer captures carry a real
    per-call table and can be replayed by supplying its 272 raw bytes.
    """
    assert len(padded) % 16 == 0
    if round_keys is None:
        round_keys = bytes(272)
    if len(round_keys) != 272:
        raise ValueError("Helios round_keys must be exactly 272 bytes")
    mem = Mem()
    INPUT, OUTPUT, TABLE = 0x1000, 0x2000, 0x3000
    mem.wr(INPUT, padded)
    mem.wr(TABLE, round_keys)
    out = bytearray()
    for off in range(0, len(padded), 16):
        pa = 0x4000
        mem.w64(pa, TABLE)          # packed[0] = 34*u64 round-key table
        mem.w64(pa + 8, INPUT + off)
        mem.w64(pa + 16, OUTPUT)
        run_block(mem, pa)
        out += mem.rd(OUTPUT, 16)
    return bytes(out)

if __name__ == "__main__":
    import json
    trace = json.load(open(r"C:\AI\3\trace3.json"))
    # replicate the unicorn env of the traced run: input bytes(1..64), block 0
    mem = Mem()
    mem.wr(0x70000200, bytes(range(1, 65)))
    pa = 0x700FEF00
    mem.w64(pa, 0x70000010)      # clobbered packed[0] (points at zero page)
    mem.w64(pa + 8, 0x70000200)
    mem.w64(pa + 16, 0x70000400)
    ok = run_block(mem, pa, trace)
    print("TRACE MATCH:", ok)
    if ok:
        print("steps:", len(trace))
        print("output:", mem.rd(0x70000400, 16).hex())
