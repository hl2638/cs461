#include <stdio.h>
#include <unistd.h>
int main(){
	syscall(11, "/bin/sh", 0, 0);
	return 0;
}
