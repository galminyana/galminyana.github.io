## Assignment #1
## Bind_Shell_TCP

### Introduction
Requirements for this assignment are to create a Shell_Bind_TCP shellcode that: 

 1. Listens on a specific port 
 2. Requires a password 
 3. If the password is correct, then Exec Shell is executed 
 4. Also, the NULL bytes (0x00) must be removed from the shellcode 

To build the shellcode, we is required the use of the linux sockets and do the following steps: 

 1. Create a socket 
 2. Bind the socket to a port 
 3. Start listenning for connections 
 4. Accept incoming connections 
 5. Ask, read, and validate the password 
 6. Duplicate `SDTIN`, `STDOUT` and `STDERR` to the socket descriptor 
 7. Execute /bin/sh for the incoming and validated conection 

In case the password is not correct, the shellcode will exit with a Segmentation Fault. The shellcode won’t care on how the program terminates. This makes sense as shellcode will be smaller in size and really does not matter how it exits. 

For Linux Sockets Programming, the following System calls are required on this assignment: 

```c
int socket(int domain, int type, int protocol); 
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); 
int listen(int sockfd, int backlog); 
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); 
int close(int sockfd); 
```
To duplicate the standard input, output and error, `dup2()` call will be used: 

```c
int dup2(int oldfd, int newfd); 
```

And to execute `/bin/sh`, will use the `execve()` call: 

```c
int execve(const char *filename, char *const argv[], char *const envp[]); 
```
### ASM Implementation
----

Will explain how we implement each step mentioned before into ASM, with the idea to make the code easy to understand. No enphasys has been put into removing NULLs and make the shellcode small (this is done later).

1. **CREATE A SOCKET**

```asm
; sock = socket(AF_INET, SOCK_STREAM, 0) 
mov rax, 41                     ; syscall number 
mov rdi, AF_INET                ; IPv4 
mov rsi, SOCK_STREAM            ; TCP connection 
mov rdx, 0                      ; IP Protocol 
syscall 
; Save the socket_id value in RDI for future use 
mov rdi, rax                    ; value returned in RAX by syscall  
```
This is the first step required for sockets, open the socket. 
To execute the sys_socket system call the arguments will have to be placed in the corresponding registers: 

 - RAX <- 41 : Syscall number. 
 - RDI <- 2 : Domain parameter. AF_INET is for IPv4. 
 - RSI <-  1 : Type parameter. SOCK_STREAM means connection oriented TCP. 
 - RDX <- 0 : Protocol. IPPROTO_IP means it’s an IP protocol 

















