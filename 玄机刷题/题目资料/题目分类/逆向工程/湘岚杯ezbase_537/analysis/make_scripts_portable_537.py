from pathlib import Path
root=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\湘岚杯ezbase_537\analysis')
p=root/'solve_537_from_static.py'
s=p.read_text(encoding='utf-8')
old="p = Path(r'Z:\\ezbase_unpacked.exe')"
new="p = Path(__file__).resolve().parent / 'ezbase_unpacked.exe'"
assert old in s, repr(old)
p.write_text(s.replace(old,new),encoding='utf-8')
q=root/'restore_upx_section_names.py'
t=q.read_text(encoding='utf-8')
t=t.replace("src = Path(r'Z:\\ezbase.exe')", "src = Path(__file__).resolve().parent / 'ezbase.exe'")
t=t.replace("dst = Path(r'Z:\\ezbase_names_restored.exe')", "dst = Path(__file__).resolve().parent / 'ezbase_names_restored.exe'")
q.write_text(t,encoding='utf-8')
print('updated static scripts to use their own directory instead of temporary subst drive Z:')
