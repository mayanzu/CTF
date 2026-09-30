import json, pathlib
path = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_easyre_560\hap_extracted\ets\sourceMaps.map")
root=json.loads(path.read_text(encoding="utf-8"))
alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def decode_vlq(s):
    out=[]; value=0; shift=0
    for ch in s:
        digit=alphabet.index(ch); cont=digit&32; value|=(digit&31)<<shift
        if cont: shift+=5; continue
        negative=value&1; magnitude=value>>1
        out.append(-magnitude if negative else magnitude)
        value=shift=0
    if shift: raise ValueError("unterminated VLQ")
    return out
for key,entry in root.items():
    prev_source=prev_line=prev_col=prev_name=0
    rows=[]
    for gen_line,row in enumerate(entry.get("mappings","").split(";"),1):
        prev_gen_col=0; points=[]
        for seg in filter(None,row.split(",")):
            vals=decode_vlq(seg); prev_gen_col+=vals[0]
            if len(vals)>=4:
                prev_source+=vals[1]; prev_line+=vals[2]; prev_col+=vals[3]
                if len(vals)>=5: prev_name+=vals[4]
                points.append((prev_line+1,prev_col,prev_gen_col))
        if points: rows.append((gen_line,points))
    originals=sorted({(line,col) for _,pts in rows for line,col,_ in pts})
    print(f"\nFILE {entry.get('file')} source={entry.get('sources')} generated_rows={len(rows)} mapped_positions={len(originals)} source_content_present={bool(entry.get('sourcesContent'))}")
    for line in sorted({x[0] for x in originals}):
        cols=sorted({col for ln,col in originals if ln==line})
        print(f" source_line {line}: columns={cols}")
