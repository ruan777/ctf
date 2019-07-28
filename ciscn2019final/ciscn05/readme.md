这题学到了新姿势
题目一开始（省略了无关紧要的代码）
```c
unsigned __int64 init()
{
  int fd; // [rsp+4h] [rbp-Ch]
  fd = open("flag", 0);
  if ( fd == -1 )
  {
    puts("no such file :flag");
    exit(-1);
  }
  dup2(fd, 666);
  close(fd);
}
```
有个dup2(fd,666),应该后面会用到

分析了下程序流程，是个在libc2.27下的double free比较容易，但是程序只能写四个字节或者两个字节，比赛的时候不知道该写哪里，赛后听大佬的分享才知道要改写 **_IO_2_1_stdin** 结构的fileno，大佬tql，orz

最后只要调用bye_bye函数scanf就会把flag打印出来

```c
pwndbg> p _IO_2_1_stdin_
$2 = {
  file = {
    _flags = -72539512, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 666, 
    _flags2 = 0, 
    _old_offset = -64870, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7f08c3d848d0 <_IO_stdfile_0_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7f08c3d82ae0 <_IO_wide_data_0>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7f08c3d7f2a0 <_IO_file_jumps>
}

```
最后bye_bye的时候就会打印出flag
```shell
what do you want to say at last? 
your message :flag{aaaaaaaaaaaaaaa} we have received...
have fun !
```
那么为什么把stdin的fileno改成666 scanf会把flag读进来呢

```c
int
__scanf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = _IO_vfscanf (stdin, format, arg, NULL);
  va_end (arg);

  return done;
}
```
scanf调用了 _IO_vfscanf

