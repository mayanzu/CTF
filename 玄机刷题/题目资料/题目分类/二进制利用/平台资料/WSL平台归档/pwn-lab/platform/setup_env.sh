#!/bin/bash
# 本地复现环境准备：创建 pwn 启动必需的文件，以及本地测试用 /flag
set -x

# 1) main() 强依赖 /mnt/VIN 与 /mnt/version，否则直接 "miss file." 退出
sudo bash -c 'printf "LSVNV2182E2123456" > /mnt/VIN'
sudo bash -c 'printf "v1.0.0"             > /mnt/version'

# 2) 其它命令读取的文件（缺失时返回 error / status_unavailable，非必需但补全更真实）
sudo bash -c 'printf "ok"                > /dev/status'
sudo bash -c 'printf "31.2304,121.4737"  > /dev/location'
sudo bash -c 'printf "2.4,2.5,2.4,2.6"   > /dev/tpms'

# 3) 本地端到端演练用的假 flag
sudo bash -c 'printf "flag{local_test}\n" > /flag'

# 4) 结果
sudo ls -l /mnt/VIN /mnt/version /dev/status /dev/location /dev/tpms /flag
sudo cat /mnt/VIN; echo; sudo cat /flag