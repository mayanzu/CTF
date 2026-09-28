"""字节序演示：同一串字节按大端 / 小端读出不同的整数。

供 handout-misc.tex 第 2 章「字节序与 struct」小节配图；所有输出均为真实运行结果。
数据取自本册真实题目文件：
- PNG 块长度字段（大端序）：pixel.png 的 IHDR 长度 = 13
- PCAP 记录长度字段（小端序）：示例值 50
- UDP 目的端口字段（大端序）：fragments.pcap 的 9000 端口
"""
import struct

png_len = b'\x00\x00\x00\x0d'          # pixel.png 里 IHDR 块长度 = 13
pcap_len = bytes.fromhex('32000000')   # 假设某条 PCAP 记录长度 = 50
udp_port = b'\x23\x28'                  # fragments.pcap 里的目的端口

print('PNG 长度字段字节          :', png_len.hex(' '))
print('  大端序解读 (PNG 规定)   :', int.from_bytes(png_len, 'big'))
print('  struct.unpack(">I") 读 :', struct.unpack('>I', png_len)[0])
print()
print('PCAP 长度字段字节         :', pcap_len.hex(' '))
print('  小端序解读 (PCAP 规定)  :', int.from_bytes(pcap_len, 'little'))
print('  struct.unpack("<I") 读 :', struct.unpack('<I', pcap_len)[0])
print()
print('同一串字节读错字节序      :', struct.unpack('>I', pcap_len)[0], '(大端) vs',
      struct.unpack('<I', pcap_len)[0], '(小端)')
print()
print('UDP 目的端口字段字节      :', udp_port.hex(' '))
print('  大端序解读 (>H, 2 字节) :', int.from_bytes(udp_port, 'big'), '= 端口 9000')
print('  struct.unpack(">H") 读  :', struct.unpack('>H', udp_port)[0])