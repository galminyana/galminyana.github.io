## Assignment #4: Create Encoding Scheme
---
---
### Introduction
---


### Egg Hunter Implementation
---

```
### ASM Implementation
---

### The PoC Code
---

#### Compiling and Run


#### Setting the POC for any shellcode


### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment03) for this assignment contains the following files:

- [EggHunter.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunter.nasm) : This is the ASM source code for the first version of the Egg Hunter. It's with NULLs and not caring on the shellcode size, but is more clear to understand the code.
- [EggHunterV2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunterV2.nasm) : This is the NULL free code for the Egg Hunter.
- [ReverseShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/ReverseShell-ExecveStack_V2.nasm) : This is the NULL free code for the Egg Hunter.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/shellcode.c) : The C template with the V2 of the Egg Hunter Shellcode and ReverseShell Shellcode, ready to compile and execute
- [pagesize.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/pagesize.c) : A C program that just prints the size of memory pages in the system

### The End
---
This pages have been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: PA-14628
 
