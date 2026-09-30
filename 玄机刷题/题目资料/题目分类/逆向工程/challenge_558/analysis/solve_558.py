#!/usr/bin/env python3
"""Reproduce challenge #558 transform using static PE findings only."""
RAW_KEY = b"lntfvpus"
KEY = bytes(b ^ i for i, b in enumerate(RAW_KEY))
TARGET = bytes.fromhex("18 59 07 28 f4 ad c8 c3 b6 3f 2d 39 ca 34 d1 8e f5 03 b0")
MASK8 = 0xff

def ksa(key):
    # Rust 0..=255 table, j = low byte(j + S[i] + (key[i % 8] XOR 0x66)), swap.
    s = list(range(256))
    j = 0
    trace = []
    for i in range(256):
        key_term = key[i % len(key)] ^ 0x66
        j = (j + s[i] + key_term) & MASK8
        before_i, before_j = s[i], s[j]
        s[i], s[j] = s[j], s[i]
        trace.append((i, key[i % len(key)], key_term, before_i, j, before_j, s[i], s[j]))
    return s, trace

def stream_state(s, ciphertext):
    i = j = 0  # Rust clears the two u16 PRGA counters after KSA.
    plaintext = bytearray()
    trace = []
    for pos, c in enumerate(ciphertext):
        i = (i + 1) & MASK8
        si_before_j = s[i]
        j = (j + si_before_j) & MASK8
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) & MASK8
        table_byte = s[t]
        nibble_swapped = ((table_byte << 4) | (table_byte >> 4)) & MASK8
        mask = (nibble_swapped + 1) & MASK8
        p = ((c - 1) & MASK8) ^ mask
        plaintext.append(p)
        trace.append((pos, i, j, si_before_j, s[i], s[j], t, table_byte, nibble_swapped, mask, c, p))
    return bytes(plaintext), trace

def encrypt(plaintext, s):
    i = j = 0
    out = bytearray()
    for p in plaintext:
        i = (i + 1) & MASK8
        j = (j + s[i]) & MASK8
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) & MASK8
        table_byte = s[t]
        nibble_swapped = ((table_byte << 4) | (table_byte >> 4)) & MASK8
        mask = (nibble_swapped + 1) & MASK8
        out.append(((p ^ mask) + 1) & MASK8)
    return bytes(out)

s, ksa_trace = ksa(KEY)
plain, stream_trace = stream_state(s.copy(), TARGET)
roundtrip = encrypt(plain, ksa(KEY)[0])
print("raw_key_ascii=", RAW_KEY.decode())
print("key_index_xor_i_hex=", KEY.hex())
print("effective_key_ascii=", KEY.decode())
print("target_len=", len(TARGET))
print("target_hex=", TARGET.hex())
print("ksa_rounds=", len(ksa_trace))
print("ksa_first8 (i,key,key^66,S_i_before,j,S_j_before,S_i_after,S_j_after)=", ksa_trace[:8])
print("prga_trace_columns=(pos,i,j,S_i_before_j,S_i_after_swap,S_j_after_swap,t,S[t],nibble_swap,mask,cipher,plain)")
for row in stream_trace:
    print("prga=", row)
print("candidate_hex=", plain.hex())
print("candidate_ascii=", plain.decode("ascii"))
print("roundtrip_hex=", roundtrip.hex())
print("roundtrip_match=", roundtrip == TARGET)
