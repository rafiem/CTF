# Profile
* Terdapat vuln pada fungsi edit_msg
* Dapat mengubah pointer dari name melalui edit_msg
* Leak canary dengan bruteforce LSB dari pointer message
* Leak libc address dengan melihat GOT "malloc_usable_size"
* Susun ROP dengan akhiran memanggil one_gadget  