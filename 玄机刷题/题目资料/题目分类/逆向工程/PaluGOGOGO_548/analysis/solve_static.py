"""Static-only reconstruction of the Go checker algorithm. Never loads or runs the PE."""
import struct, sys
from pathlib import Path
MASK64=(1<<64)-1
INT32MAX=(1<<31)-1

def pe_sections(data):
    pe=struct.unpack_from('<I',data,0x3c)[0]
    n=struct.unpack_from('<H',data,pe+6)[0]
    optlen=struct.unpack_from('<H',data,pe+20)[0]
    opt=pe+24
    imagebase=struct.unpack_from('<Q',data,opt+24)[0]
    sb=opt+optlen
    out=[]
    for i in range(n):
        o=sb+40*i
        name=data[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
        vsize,va,rsize,rptr=struct.unpack_from('<IIII',data,o+8)
        out.append((name,va,vsize,rptr,rsize))
    return imagebase,out

def va_to_offset(data,va):
    imagebase,sections=pe_sections(data)
    rva=va-imagebase
    for name,srva,vsize,rptr,rsize in sections:
        if srva<=rva<srva+rsize:
            return rptr+(rva-srva)
    raise ValueError(f'VA 0x{va:x} has no raw file mapping')

def seedrand(x):
    # math/rand Go 1.22.4 rngSource.Seed, confirmed from disassembly constants.
    return (48271*x) % INT32MAX

def go_seed(seed,cooked):
    # Go math/rand rngSource.Seed: tap=0, feed=rngLen-rngTap=334.
    seed%=INT32MAX
    if seed<0: seed+=INT32MAX
    if seed==0: seed=89482311
    x=seed
    vec=[]
    for i in range(-20,607):
        x=seedrand(x)
        if i>=0:
            u=(x<<40)&MASK64
            x=seedrand(x); u^=(x<<20)&MASK64
            x=seedrand(x); u^=x
            u^=cooked[i]
            vec.append(u&MASK64)
    return [vec,0,334]

def int63(state):
    vec,tap,feed=state
    tap=(tap-1)%607; feed=(feed-1)%607
    v=(vec[feed]+vec[tap])&MASK64
    vec[feed]=v
    state[1]=tap; state[2]=feed
    return v&((1<<63)-1)

def int31(state):
    return (int63(state)>>32)&0x7fffffff

def intn(state,n):
    if n<=0: raise ValueError('n must be positive')
    if n&(n-1)==0:
        return int31(state)&(n-1)
    maxv=(1<<31)-1-(1<<31)%n
    draws=0
    while True:
        v=int31(state); draws+=1
        if v<=maxv:
            return v%n

def main():
    p=Path(sys.argv[1]); data=p.read_bytes()
    # The rngCooked table address was recovered from rngSource.Seed disassembly:
    # lea rdi,[rip+0xbd17d] at VA 0x494c5c => VA 0x551de0.
    cooked_va=0x551de0; cooked_off=va_to_offset(data,cooked_va)
    cooked=list(struct.unpack_from('<607q',data,cooked_off))
    print(f'input file: {p}; size={len(data)}')
    print(f'rngCooked VA=0x{cooked_va:x}, file offset=0x{cooked_off:x}, entries={len(cooked)}')
    seed=0x3e4
    st=go_seed(seed,cooked)
    vals=[intn(st,100) for _ in range(10)]
    idx=intn(st,2)
    key=vals[idx]
    print(f'rand.Seed({seed}) -> Intn(100) array={vals}')
    print(f'next Intn(2) index={idx}; GetValue key={key}')
    # The disassembly compares an 84-byte hardcoded ASCII string at VA 0x4bf204.
    target_va=0x4bf204; target_off=va_to_offset(data,target_va)
    target=data[target_off:target_off+0x54].decode('ascii')
    toks=target.split(',')
    encoded=[int(x,16) for x in toks]
    print(f'target VA=0x{target_va:x}, file offset=0x{target_off:x}, bytes={len(target)}, tokens={len(encoded)}')
    print(f'target={target}')
    codepoints=[v-key-(i%5) for i,v in enumerate(encoded)]
    flag=''.join(chr(cp) for cp in codepoints)
    print('decoded codepoints:', ' '.join(f'U+{cp:04X}' for cp in codepoints))
    print(f'candidate={flag}')
    forward=','.join(f'0x{ord(ch)+key+(i%5):x}' for i,ch in enumerate(flag))
    print(f'forward={forward}')
    print(f'forward_matches_target={forward==target}')
    print(f'flag_prefix_ok={flag.startswith("flag{") and flag.endswith("}")}')

if __name__=='__main__':main()

