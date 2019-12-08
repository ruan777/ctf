A = arch
A == ARCH_X86_64 ? next : dead
A = sys_number 
A == close ? dead : next
A == open ? next : ok
A = args[0]
A &= 0xff
A == 0x7c ? dead : next
ok:
return ALLOW
dead:
return ERRNO(0)