K = "012ab9c3478d56ef"
MASK64 = (1 << 64) - 1
SEPARATORS_AFTER = {7, 12, 17, 22}

# Build F_n mod 16 through n=25 to expose the 24-step cycle boundary.
fib = [0, 1]
for _ in range(2, 26):
    fib.append((fib[-1] + fib[-2]) & 0xF)
print("F_n mod 16, n=0..25:", fib)
print("Cycle check: F_24 mod 16 =", fib[24], "; F_25 mod 16 =", fib[25])

seed = 1
chars = []
print("i | seed | seed%24 | F_(seed%24)%16 | K[index] | output")
for i in range(32):
    period_index = seed % 24
    k_index = fib[period_index]
    char = K[k_index]
    chars.append(char)
    piece = char + ("-" if i in SEPARATORS_AFTER else "")
    print(f"{i:02d} | {seed:20d} | {period_index:02d} | {k_index:02d} | {char} | {piece}")
    seed = (seed * 8 + i + 64) & MASK64

body = "".join(char + ("-" if i in SEPARATORS_AFTER else "") for i, char in enumerate(chars))
print("RAW:", "".join(chars))
print("RESULT:", f"flag{{{body}}}")
