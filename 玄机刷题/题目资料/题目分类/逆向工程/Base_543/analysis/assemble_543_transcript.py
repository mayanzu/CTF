"""Assemble the #543 command and output records into one human-readable transcript."""
from __future__ import annotations
import pathlib

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
REC = ROOT / "records"
OUT = REC / "543_command_transcript.txt"
parts = [
    "玄机 #543《你知道Base么》完整静态分析命令与输出汇总",
    "约束：只静态读取与反汇编；没有执行附件，也没有连接/提交玄机平台。",
    "项目工作目录：C:\\Users\\mzj\\Desktop\\CTF",
    "",
    "I. 探查与文件类型确认（PowerShell）",
    "COMMAND> Get-Location; Get-ChildItem -Force '<题目目录>' | Select Mode,Length,Name; Get-FileHash -Algorithm SHA256 -LiteralPath '<原始RAR>' | Format-List",
    "OUTPUT> Path=C:\\Users\\mzj\\Desktop\\CTF",
    "OUTPUT> 题目目录仅见 originals 子目录",
    "OUTPUT> RAR SHA256=3FEC5E1930230660DCABDF0F31F4D97F8BB980D67306242D48A4377B74590801",
    "COMMAND> Get-Command 7z.exe,7za.exe,rar.exe,unrar.exe,tar.exe -ErrorAction SilentlyContinue | Select Name,Source",
    "OUTPUT> tar.exe C:\\WINDOWS\\system32\\tar.exe（本机未发现7z/UnRAR）",
    "COMMAND> Format-Hex -LiteralPath '<原始RAR>' | Select-Object -First 3; tar.exe -tf '<原始RAR>'",
    "OUTPUT> 文件头字节 52 61 72 21 1A 07 01 00，即RAR5；第一次控制台中文显示乱码，随后用Python捕获tar原始stdout并按GBK解码校正。",
    "",
    "II. 安全归档清单与解压",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\inventory_543.py",
    "OUTPUT> 两成员：你知道Base么/你知道Base么.exe（70144 bytes）；你知道Base么（目录项）。路径检查 members=2, members_safe=True, unsafe_members=[]。",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\extract_543.py",
    "OUTPUT> tar.exe -xf <RAR> -C <新建空目录> -- '你知道Base么/你知道Base么.exe' '你知道Base么'；EXIT_CODE=0。",
    "OUTPUT> EXE SHA256=EF7DEACF6594E9353E934564B38761E8AAF614EBF39DCB17EFED36263DF2C773；70,144 bytes。",
    "",
    "III. PE静态分析（包括失败分支）",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\static_543.py",
    "OUTPUT> strings/strings -el 成功；objdump 的 Unicode 源路径尝试失败，stderr 为 objdump: <中文路径>: No such file or directory。失败原日志与空输出均保留。",
    "原因与处理> MSYS2 objdump 对当前Unicode路径无法打开；未更改源文件。以 Python shutil.copyfile 复制到纯ASCII临时路径并核对SHA256后再调用objdump。",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\static_543_ascii_retry.py",
    "OUTPUT> 源与ASCII副本SHA256同为 EF7DEACF6594E9353E934564B38761E8AAF614EBF39DCB17EFED36263DF2C773。",
    "OUTPUT> PE header/section/imports、ASCII/UTF16 strings、Intel完整反汇编均已生成；完整反汇编文件大小 1,083,898 bytes。",
    "OUTPUT> PE32+ amd64、ImageBase 0x140000000、入口RVA 0x11299、入口VA 0x140011299、Subsystem Windows CUI、TimeDate 2025-05-02 20:56:54。",
    "COMMAND> strings -a -t x -n 3 C:\\Users\\mzj\\Desktop\\CTF\\challenge543_static.exe | Select-String 'input|error|Successful|failed|level|CTFer|key|Table|flag|%8s|%64s|%29s'",
    "OUTPUT> input1@0xa7b0, input3@0xa7d0, error!@0xaac8, Successful!@0xaad8, You are failed!!!@0xaae8, You have passed the second level!!@0xab00, Hello CTFer!@0xab30, give me your key@0xab48, %8s@0xab60, you failed!!!@0xab68, You have passed the first level!!!@0xab80, Where is my Base_Table???@0xabb0, Plz input your found Table:@0xabd0, %64s@0xabf4, Plz input Your flag:@0xac00, %29s@0xac1c。",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\pe_layout_543.py",
    "OUTPUT> 完整section/RVA/raw偏移、任务字符串VA映射与直接反汇编引用在 analysis\\pe_layout_string_map.txt；字符串引用指向 0x14001c148 等位置；控制流中 Base32编码器为0x140012ae0、RC4 KSA为0x140011d10、加法PRGA为0x140011ea0、逐字节对比为0x1400124f0/0x140012400。",
    "",
    "IV. 保留的失败尝试",
    "COMMAND> 一次把反斜杠+n作为字面字符传给 python -c 的多行代码尝试",
    "OUTPUT> SyntaxError: unexpected character after line continuation character；没有执行任何算法。改为保存 analysis\\decrypt_543_key.py 并运行。",
    "COMMAND> objdump 使用Unicode源路径的第一次尝试",
    "OUTPUT> exit 1 / No such file or directory；完整stderr在 records\\543_static_analysis_transcript.txt；没有文件损坏或写入。",
    "",
    "V. 关键候选与正向验证脚本",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\decrypt_543_key.py",
    "OUTPUT> 解密 DWORD 0xa92f3865,0x9e60e953 得到 y0uokTea；32轮正向加密严格还原这两个 DWORD。",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\derive_543_table_flag.py",
    "OUTPUT> 从反汇编立即数恢复64字节目标；以 y0uokTea 复现 RC4 KSA + 加法PRGA，逆得64字符 Base_Table。完整输出保存在 records\\543_table_flag_derivation.txt。",
    "COMMAND> python .\\玄机刷题\\题目资料\\题目分类\\逆向工程\\Base_543\\analysis\\verify_543_end_to_end.py",
    "OUTPUT> 第一关正向精确匹配；RC4/additive 64/64字节匹配；完整30字节 flag 的48字符 Base32输出与内嵌目标48/48字节匹配。完整结果在 records\\543_final_verification.txt。",
    "",
    "VI. ASCII临时副本清理尝试",
    "COMMAND> Remove-Item -LiteralPath 'C:\\Users\\mzj\\Desktop\\CTF\\challenge543_static.exe' -Force",
    "OUTPUT> exec_command 在命令执行前返回 Rejected (blocked by policy)；命令未执行。后续只读检查确认临时副本仍存在，SHA256与项目内提取件相同。没有改用其他删除方式。",
    "",
    "逐次原生命令、退出码、stderr与标准输出文件清单：",
]
for name in [
    "543_inventory_transcript.txt",
    "543_extraction_transcript.txt",
    "543_static_analysis_transcript.txt",
    "543_static_analysis_retry_transcript.txt",
    "543_key_decrypt_trace.txt",
    "543_table_flag_derivation.txt",
    "543_final_verification.txt",
]:
    p=REC/name
    if p.exists():
        parts += ["", "="*78, f"VERBATIM ATTACHED RECORD: {name}", "="*78, p.read_text(encoding="utf-8",errors="replace").rstrip()]
parts += [
    "",
    "附属原始静态分析输出：analysis\\objdump_pe_header_ascii.txt、objdump_sections_ascii.txt、objdump_imports_ascii.txt、strings_ascii_ascii.txt、strings_utf16le_ascii.txt、objdump_disassembly_intel_ascii.txt、pe_layout_string_map.txt。",
    "说明：objdump_Disassembly保存完整1MB输出。探索时的地址区间查询可直接按目标地址从完整反汇编重现；本汇总同时保留每项分析的专用命令脚本与解释性输出。",
]
OUT.write_text("\n".join(parts)+"\n",encoding="utf-8")
print("transcript="+str(OUT))
print("bytes="+str(OUT.stat().st_size))
