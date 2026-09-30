from hashlib import md5

# Correct alphabet read from unpacked PE RVA 0x5e66. The leading g is required.
alphabet = 'gPalu_996!?'
target = '1145141919810'

candidate = ''.join(alphabet[int(digit)] for digit in target)
transformed = ''.join(str(alphabet.find(ch)) for ch in candidate)
assert transformed == target
assert len(candidate) == len(target)
digest = md5(candidate.encode('ascii')).hexdigest()
flag = f'palu{{{digest}}}'
print(f'alphabet={alphabet!r}')
print(f'alphabet_positions={list(enumerate(alphabet))}')
print(f'target={target}')
print(f'candidate_input={candidate!r}')
print(f'forward_find_transform={transformed}')
print(f'md5_input_ascii={digest}')
print(f'candidate_flag={flag}')
