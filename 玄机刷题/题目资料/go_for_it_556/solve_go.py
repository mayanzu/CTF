import pathlib, re, subprocess, hashlib
here=pathlib.Path(__file__).resolve().parent
root=here/"probes"
debugger=here/"go_debugger.exe"
program=here/"go.exe"
base=b"A"*32

def capture(name, data):
    inp=root/(name+".txt")
    inp.write_bytes(data)
    cmd=[debugger,program,str(inp)]
    print("\nCOMMAND:",repr(cmd),"input_hex=",data.hex(),flush=True)
    cp=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
    print("exit_code:",cp.returncode,flush=True)
    print("stdout:\n"+cp.stdout,flush=True)
    print("stderr:\n"+cp.stderr,flush=True)
    match=re.search(r"transformed=([0-9a-f]{64})",cp.stdout)
    exp=re.search(r"expected=([0-9a-f]{64})",cp.stdout)
    if cp.returncode or not match or not exp:
        raise RuntimeError("debug capture failed: "+name)
    return bytes.fromhex(match.group(1)),bytes.fromhex(exp.group(1))

base_out,target=capture("matrix_baseline",base)
columns_by_block=[[] for _ in range(4)]
for block in range(4):
    for pos in range(8):
        for bit in range(7):
            offset=block*8+pos
            sample=bytearray(base)
            sample[offset]^=1<<bit
            out,exp=capture(f"b{block}_p{pos}_bit{bit}",bytes(sample))
            if exp != target:
                raise RuntimeError("target constant drift")
            delta=bytes(a^b for a,b in zip(out,base_out))
            expected_delta=bytearray(32)
            block_delta=delta[block*8:(block+1)*8]
            expected_delta[block*8:(block+1)*8]=block_delta
            if delta != bytes(expected_delta):
                raise RuntimeError(f"input block {block}, byte {pos}, bit {bit} altered outside its output block: {delta.hex()}")
            columns_by_block[block].append(int.from_bytes(block_delta,"big"))
    print(f"verified block {block}: 56 ASCII input-bit basis vectors affect only output bytes {8*block}..{8*block+7}",flush=True)

def solve(cols, goal):
    basis={}
    for k,vec0 in enumerate(cols):
        vec=vec0
        combo=1<<k
        for pivot in sorted(basis,reverse=True):
            if (vec>>pivot)&1:
                row,mask=basis[pivot]
                vec^=row; combo^=mask
        if vec:
            basis[vec.bit_length()-1]=(vec,combo)
    residue=goal
    combo=0
    for pivot in sorted(basis,reverse=True):
        if (residue>>pivot)&1:
            row,mask=basis[pivot]
            residue^=row; combo^=mask
    return len(basis),combo,residue

candidate=bytearray()
for block in range(4):
    goal=int.from_bytes(bytes(a^b for a,b in zip(target[8*block:8*block+8],base_out[8*block:8*block+8])),"big")
    rank,combo,residue=solve(columns_by_block[block],goal)
    print(f"block {block}: GF(2) rank={rank}/56 residue={residue:016x} solution_mask={combo:014x}",flush=True)
    if residue:
        raise RuntimeError(f"target block {block} is outside the 7-bit ASCII affine image")
    for pos in range(8):
        mask=0
        for bit in range(7):
            idx=pos*7+bit
            if (combo>>idx)&1: mask|=1<<bit
        candidate.append(0x41^mask)

candidate=bytes(candidate)
print("candidate_hex:",candidate.hex(),flush=True)
print("candidate_repr:",repr(candidate),flush=True)
print("candidate_utf8:",candidate.decode("utf-8","backslashreplace"),flush=True)
print("candidate_ascii_whitespace_positions:",[i for i,b in enumerate(candidate) if b in b" \\t\\r\\n\\v\\f"],flush=True)
candidate_path=root/"candidate.txt"
candidate_path.write_bytes(candidate)
print("candidate_file:",candidate_path,"bytes:",len(candidate),"sha256:",hashlib.sha256(candidate).hexdigest(),flush=True)
# Critical direct verification uses the original challenge process, not the debugger harness.
verify_cmd=[program]
print("\nCOMMAND:",repr(verify_cmd),"stdin_file=",str(candidate_path),flush=True)
with candidate_path.open("rb") as fin:
    cp=subprocess.run(verify_cmd,stdin=fin,capture_output=True,timeout=20)
print("direct_exit_code:",cp.returncode,flush=True)
print("direct_stdout_bytes:",repr(cp.stdout),flush=True)
print("direct_stderr_bytes:",repr(cp.stderr),flush=True)
print("direct_stdout_utf8:",cp.stdout.decode("utf-8","backslashreplace"),flush=True)
print("local_checker_accepts_candidate:",b"Right!" in cp.stdout and b"Wrong!" not in cp.stdout and cp.returncode==0,flush=True)
# Also stop at the actual comparison point and compare the candidate transform to target.
transformed,expected=capture("candidate_recheck",candidate)
print("candidate_transform_matches_target:",transformed==expected==target,flush=True)
print("candidate_final_validation:",transformed==target and b"Right!" in cp.stdout and b"Wrong!" not in cp.stdout and cp.returncode==0,flush=True)
