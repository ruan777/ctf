#include <linux/seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <signal.h>
#include <sys/prctl.h>

static void install_seccomp() {
    static unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,2,0,0,0,21,0,3,0,0,0,0,0,21,0,2,0,60,0,0,0,21,0,1,0,231,0,0,0,6,0,0,0,0,0,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
    struct prog {
        unsigned short len;
        unsigned char *filter;
    } rule = {
        .len = sizeof(filter) >> 3,
        .filter = filter
    };
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0){ 
        _exit(2); 
    }
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0){ 
        _exit(2); 
    }
}



void handler(int sig){
	_exit(2);
}

void init(void){
    // setvbuf(stdin,NULL,_IONBF,0);
    // setvbuf(stdout,NULL,_IONBF,0);
    // setvbuf(stderr,NULL,_IONBF,0);
    signal(SIGALRM, handler);
	alarm(0x3c);
    install_seccomp();
}

void read_n(char* buf,int size){
	read(0,buf,size);
}

int main(){
	char buf[0x10];
    init();
    read_n(buf,0x100);
    return 0;
}