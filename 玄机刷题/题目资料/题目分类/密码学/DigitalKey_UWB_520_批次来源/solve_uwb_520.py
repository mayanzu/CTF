from pathlib import Path
import base64, hashlib, json, sqlite3, subprocess

DB = Path(__file__).parent / 'extracted' / 'digital_key_trace.sqlite'
OPENSSL = r'C:\msys64\mingw64\bin\openssl.exe'
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

def point_add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p == q:
        slope = ((3*x1*x1 + A) * pow(2*y1, -1, P)) % P
    else:
        slope = ((y2-y1) * pow((x2-x1) % P, -1, P)) % P
    x3 = (slope*slope - x1 - x2) % P
    y3 = (slope*(x1-x3) - y1) % P
    return x3, y3

def point_mul(k, point=(GX, GY)):
    result = None
    addend = point
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

con = sqlite3.connect('file:' + str(DB).replace('\\', '/') + '?mode=ro', uri=True)
sigs = con.execute('SELECT session_id,signed_json,digest_hex,r_hex,s_hex FROM auth_signatures ORDER BY ts').fetchall()
meta = dict(con.execute('SELECT key,value FROM meta'))
blob = con.execute('SELECT alg,key_hint,iv_hex,ciphertext_b64 FROM protected_vehicle_blob').fetchone()
con.close()
print('database=', DB)
print('signature_count=', len(sigs))
for row in sigs:
    sid, payload, digest, rh, sh = row
    calc = hashlib.sha256(payload.encode()).hexdigest()
    print('signature=', sid, 'digest_field_matches_signed_json_sha256=', calc == digest)
    print('session=', sid, 'nonce_tag=', 'rng-slot-07', 'r=', rh, 's=', sh)

z1, z2 = int(sigs[0][2],16), int(sigs[1][2],16)
r = int(sigs[0][3],16)
s1, s2 = int(sigs[0][4],16), int(sigs[1][4],16)
qx, qy = int(meta['public_key_x'],16), int(meta['public_key_y'],16)
print('same_r=', sigs[0][3] == sigs[1][3])
print('same_curve=', meta['public_key_curve'])
print('public_key_x=', meta['public_key_x'])
print('public_key_y=', meta['public_key_y'])
solutions=[]
for epsilon in (1,-1):
    denominator = (s1 - epsilon*s2) % N
    k = ((z1-z2) * pow(denominator,-1,N)) % N
    d = ((s1*k-z1) * pow(r,-1,N)) % N
    pub = point_mul(d)
    print('epsilon=',epsilon,'nonce_k=',format(k,'064x'),'private_d=',format(d,'064x'),'public_key_matches=',pub==(qx,qy))
    if pub == (qx,qy): solutions.append((epsilon,k,d))
if len(solutions) != 1:
    raise SystemExit('Expected exactly one ECDSA key matching recorded public key')
epsilon,k,d=solutions[0]
for idx,(sid,payload,digest,rh,sh) in enumerate(sigs):
    z=int(digest,16); s=int(sh,16); actual_k=k if idx==0 else epsilon*k % N
    valid=(pow(s,-1,N)*(z+int(rh,16)*d)%N)==actual_k
    print('ecdsa_equation_valid=',sid,valid)
    if not valid: raise SystemExit('ECDSA verification equation failed')
d_bytes=d.to_bytes(32,'big')
key=hashlib.sha256(d_bytes).digest()[:16]
print('recovered_private_key_32byte_hex=',d_bytes.hex())
print('derived_sm4_key_hex=',key.hex())
print('key_hint=',blob[1])
print('cipher=',blob[0])
print('iv_hex=',blob[2])
ciphertext=base64.b64decode(blob[3],validate=True)
result=subprocess.run([OPENSSL,'enc','-d','-sm4-cbc','-K',key.hex(),'-iv',blob[2]],input=ciphertext,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
print('openssl_returncode=',result.returncode)
if result.stderr: print('openssl_stderr=',result.stderr.decode('utf-8','replace').strip())
if result.returncode != 0: raise SystemExit('SM4-CBC decryption failed')
plaintext=result.stdout
print('plaintext_length=',len(plaintext))
print('plaintext_utf8=',plaintext.decode('utf-8','replace'))
try:
    obj=json.loads(plaintext)
    print('plaintext_json=',json.dumps(obj,ensure_ascii=False,indent=2))
    for key_name,value in obj.items():
        if 'flag' in key_name.lower(): print('candidate_flag=',value)
except json.JSONDecodeError:
    pass

