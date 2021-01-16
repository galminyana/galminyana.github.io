## Assignment #1
## Bind_Shell_TCP

### Introduction
Requirements for this assignment are to create a Shell_bind_tcp shellcode that: 

1. Listens on a specific port 
2. Requires a password 
3.If the password is correct, then Exec Shell is executed 
4.Also, the NULL bytes (0x00) must be removed from the shellcode 

To build the shellcode, we will require the use of the linux sockets and do the following steps: 

1. Create a socket 
2. Bind the socket to a port 
3. Start listenning for connections 
4. Accept incoming connections 
5. Ask, read, and validate the password 
6. Duplicate SDTIN, STDOUT and STDERR to the socket 
7. Execute /bin/sh for the incoming and validated conection 

In case the password is not correct, we will exit with a Segmentation Fault. The shellcode won’t care on how the program terminates. This makes sense as shellcode will be smaller in size and really does not matter how it exits. 

For Linux Sockets Programming, the following System calls are required on this assignment: 

