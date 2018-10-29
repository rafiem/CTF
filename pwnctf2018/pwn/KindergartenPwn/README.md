# Kindergarten Pwn
* Kita dapat melihat dan menulis 1 byte dari &array tiap loop
* Terdapat vuln Out of Bound, dimana kita bisa ngeleak address sebelum &array dan overwrite
* Leak GOT setvbuf()
* Overwrite EXIT@GOT pada akhir program dengan One_gadget