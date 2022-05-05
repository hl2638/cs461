.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
mov $0xb, %eax

mov $file, %ebx
mov $0, %ecx
mov $0, %edx

int $0x80
leave
ret

.data
file:
.string	"/bin/sh"
