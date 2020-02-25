from pwn import*
def add(size,content):
	p.sendline('1')
	p.sendlineafter('size',str(size))
	p.sendlineafter('content',content)
def puts():
	p.sendline('2')

