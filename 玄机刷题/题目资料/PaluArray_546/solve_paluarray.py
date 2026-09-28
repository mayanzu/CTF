from hashlib import md5
alphabet = 'Palu_996!?'
target = '1145141919810'
# string.find in the disassembled validator returns the first matching position;
# this matters because '9' occurs twice in the alphabet.
by_index = {i: ch for i, ch in enumerate(alphabet)}
flag_input = ''.join(by_index[int(d)] for d in target)
transformed = ''.join(str(alphabet.find(ch)) for ch in flag_input)
assert transformed == target
payload = md5(flag_input.encode('ascii')).hexdigest()
flag = f'palu{{{payload}}}'
print(f'alphabet={alphabet!r}')
print(f'target={target}')
print(f'input={flag_input!r}')
print(f'transformed={transformed}')
print(f'md5_input_ascii={md5(flag_input.encode("ascii")).hexdigest()}')
print(f'candidate_flag={flag}')
