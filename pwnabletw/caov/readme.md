c++的operator=操作如果没有返回对象的引用，会留下一个未初始化的对象
```c
unsigned __int64 edit()
{
  __int64 v0; // rax
  __int64 v1; // rax
  db *a1; // [rsp+0h] [rbp-80h]
  __int64 v4; // [rsp+30h] [rbp-50h]
  unsigned __int64 v5; // [rsp+68h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  construter((db *)&a1);
  copy_con((__int64)&v4, (db *)&a1, golbal);
  destructer((db *)&v4);
```
注意v4在栈中的位置，再结合set_name函数就可任意地址free
