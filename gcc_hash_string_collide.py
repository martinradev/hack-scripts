from z3 import *
import sys

# I recommend using small string lengths, like 1 and 9

mul = 0xc6a4a7935bd1e995
seed = 0xc70f6907

def wrap(v):
    v = v % (2**64)
    return v

def shift_mix(v):
    return v ^ (v >> 47)

def hh(data):
    h = seed ^ wrap(len(data) * mul)
    for u in range(0, int(len(data) / 8) * 8, 8):
        tmp = int.from_bytes(data[u:u+8], 'little')
        dd = wrap(shift_mix(wrap(tmp * mul)) * mul)
        h = dd ^ h
        h = wrap(h * mul)

    if len(data) % 8 != 0:
        rem = len(data) % 8
        tmp = int.from_bytes(data[-rem:], 'little')
        h = h ^ tmp
        h = wrap(h * mul)

    h = wrap(shift_mix(h) * mul)
    h = shift_mix(h)
    return h

s = Solver()

inp = []
hfinal = []

def create_hash(name, l):
    def cc(q):
        return name + "_" + q

    mul_var = BitVec(cc("mul"), 64)
    s.add(mul_var == mul)
    len_var = BitVec(cc("len"), 64)
    s.add(len_var == l)
    h_init = BitVec(cc("h_init"), 64)
    s.add(h_init == (mul_var * len_var) ^ seed)

    hprev = h_init
    cinp = []
    for u in range(0, int(l / 8) * 8, 8):
        data_var = BitVec(cc(f"data_var_{u}"), 64)
        for z in range(0, 8):
            tmp = BitVec(cc(f"symb_{u}_{z}"), 64)
            s.add(tmp == LShR(data_var, z * 8) & 0xFF)
            s.add(tmp != 0x0)
        cinp.append(data_var)
        tmp = BitVec(cc(f"tmp_{u}"), 64)
        s.add(tmp == mul * data_var)
        dd = BitVec(cc(f"dd_{u}"), 64)
        s.add(dd == tmp ^ LShR(tmp, 47))
        dd2 = BitVec(cc(f"dd2_{u}"), 64)
        s.add(dd2 == dd * mul)
        h0 = BitVec(cc(f"h0_{u}"), 64)
        s.add(h0 == dd2 ^ hprev)
        h1 = BitVec(cc(f"h1_{u}"), 64)
        s.add(h1 == h0 * mul)
        hprev = h1

    if l % 8 != 0:
        delta = l % 8
        data_var = BitVec(cc(f"data_var_spec"), 64)
        for z in range(0, delta):
            tmp = BitVec(cc(f"spec_{z}"), 64)
            s.add(tmp == LShR(data_var, z * 8) & 0xFF)
            s.add(tmp <= 0x80)
            s.add(tmp != 0x0)
        for z in range(delta, 8):
            tmp = BitVec(cc(f"spec_{z}"), 64)
            s.add(tmp == LShR(data_var, z * 8) & 0xFF)
            s.add(tmp == 0)
        cinp.append(data_var)

        tmp = BitVec(cc(f"tmp_spec"), 64)
        s.add(tmp == hprev ^ data_var)
        tmp2 = BitVec(cc(f"tmp2_spec"), 64)
        s.add(tmp2 == tmp * mul)
        hprev = tmp2

    hfinal.append(hprev)
    inp.append(cinp)

if len(sys.argv) != 3:
    print("Usage: python3 script a_string_len b_string_len")
    exit(-1)

ls = [int(sys.argv[1]), int(sys.argv[2])]
create_hash("h0", ls[0])
create_hash("h1", ls[1])

s.add(inp[0][0] != inp[1][0])
s.add(hfinal[0] == hfinal[1])

if s.check() == unsat:
    print("No collision found")
    exit(-1)

m = s.model()

def pr(i):
    res = b""
    for u in range(0, int((ls[i] + 7) / 8)):
        res += m[inp[i][u]].as_long().to_bytes(8, 'little')
    return res[:ls[i]]

s0 = pr(0)
s1 = pr(1)
print("Found:")
print(f"input={s0}, hash={m[hfinal[0]]}")
print(f"input={s1}, hash={m[hfinal[1]]}")
