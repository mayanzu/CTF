import pathlib, re, subprocess
here=pathlib.Path(__file__).resolve().parent
root=here/"probes"
debugger=here/"go_debugger.exe"
program=here/"go.exe"
base=b"A"*32
probes={"base_Ax32":base,"first_at":b"@"+base[1:],"first_C":b"C"+base[1:],"first_B":b"B"+base[1:]}
outputs={}
for name,data in probes.items():
    inp=root/(name+".txt"); inp.write_bytes(data)
    cmd=[debugger,program,str(inp)]
    print("\nCOMMAND:",repr(cmd),"input_hex=",data.hex(),flush=True)
    cp=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
    print("exit_code:",cp.returncode,flush=True)
    print("stdout:\n"+cp.stdout,flush=True)
    print("stderr:\n"+cp.stderr,flush=True)
    match=re.search(r"transformed=([0-9a-f]{64})",cp.stdout)
    exp=re.search(r"expected=([0-9a-f]{64})",cp.stdout)
    if not match: raise RuntimeError(f"no transformed bytes for {name}")
    outputs[name]=bytes.fromhex(match.group(1))
    if exp: print("expected_hex:",exp.group(1),flush=True)

def bxor(*xs):
    return bytes(__import__("functools").reduce(lambda a,x:a^x,col,0) for col in zip(*xs))
linearity_rhs=bxor(outputs["base_Ax32"],outputs["first_at"],outputs["first_C"])
print("\nXOR-affine test: F(B first byte) == F(A) xor F(@) xor F(C):", outputs["first_B"]==linearity_rhs,flush=True)
print("predicted:",linearity_rhs.hex(),flush=True)
print("observed :",outputs["first_B"].hex(),flush=True)
