#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stack>
#include <string>
#include <map>
using namespace	std;

const int SIZE = 0x400;

void handler(int sig){
	puts("time out!");
	_exit(2);
}

static void install_seccomp() {
  static unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,11,62,0,0,192,32,0,0,0,0,0,0,0,53,0,9,0,0,0,0,64,21,0,7,0,2,0,0,0,21,0,6,0,1,1,0,0,21,0,5,0,0,0,0,0,21,0,4,0,1,0,0,0,21,0,3,0,12,0,0,0,21,0,2,0,60,0,0,0,21,0,1,0,231,0,0,0,6,0,0,0,0,0,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}

void init(void){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
    signal(SIGALRM, handler);
	alarm(0x78);
    install_seccomp();
}



struct brain_fck{
	char data[SIZE];	// data
	string code;	// brain fuck code
};

int	main(void)
{
	brain_fck bf; 

	stack<int>	left_Bracket;
	map<int,int> another_Bracket;	// record the bracket idx
	bool code_ok = true;
	char ch;
	
	init();

	while(1)
	{	
		memset(bf.data,0,SIZE);
		bf.code.clear();

		cout << "enter your code:" << endl;

		while(1){	// read bf code
			read(0,&ch,1);
			if(ch == '\n')
				break;
			bf.code += ch;
		}
		
		for(int i = 0;i < bf.code.length();i++)	// check the code and match the bracket
		{
			if(bf.code[i] == '[')
				left_Bracket.push(i);
			else if(bf.code[i] == ']')
			{
				if(left_Bracket.empty())
				{
					code_ok = false;
					break;
				}
				int	left_barcket_index = left_Bracket.top();;
				left_Bracket.pop();
				another_Bracket[i] = left_barcket_index;
				another_Bracket[left_barcket_index] = i;
			}
		}

		if(!left_Bracket.empty())
			code_ok = false;

		if(!code_ok)				// barcket not matched
		{
			puts("invalid code!");
			continue;
		}

	
		cout << endl << "running...." << endl;

		int	i = 0;
		char* cur = bf.data;
		for(i = 0;i < bf.code.length();i++)
		{
			if(bf.code[i] == '>')
			{
				cur++;
				if(cur > bf.data + SIZE)			// oob
				{
					puts("invalid operation!");
					exit(-1);
				}
			}
			else if(bf.code[i] == '<')
			{
				cur--;
				if(cur < bf.data)			// oob
				{
					puts("invalid operation!");
					exit(-1);
				}
			}
			else if(bf.code[i] == '+')
				++ (*cur);
			else if(bf.code[i] == '-')
				-- (*cur);
			else if(bf.code[i] == '.')
				write(1,cur,1);
			else if(bf.code[i] == ',')
				read(0,cur,1);
			else if(bf.code[i] == '[')
			{
				if(*cur == 0)
					i = another_Bracket[i];
			}
			else if(bf.code[i] == ']')
			{
				if(*cur)
					i = another_Bracket[i];
			}
		}

		cout << endl  << "done! your code: " << bf.code << endl;
		cout << "want to continue?" << endl;
		read(0,&ch,1);
		if(ch != 'y' && ch != 'Y')
			break;
	}
	return 0;
}


