## Assignment #3: Egg Hunter Shellcode
---
---
### Introduction
---
The objective of this assignment is to create an Egg Hunter Shellcode. For that is required to:

- Research and study about Egg Hunter Shellcode
- Create a working demo of the Egg Hunter
- The demo has to be easily configurable for different payloads

A must read paper that came during the research is [**_Safely Searching Process Virtual Address Space_**](http://www.orkspace.net/secdocs/Other/Misc/Safely%20Searching%20Process%20Virtual%20Address%20Space.pdf) from **_skape_**. It describes what a Egg Hunter is, the requirements for it to safely do it’s job, and ways to search in memory for that “egg”. 

### What's an Egg Hunter Shellcode
---
When we want to exploit a buffer overflow vulnerability injecting shellcode to it, we can find out that the space remaining in the buffer is too small to place our entire shellcode. 

Here is when the Egg Hunter Technique comes in place: An “egg” is placed at the begining of the shellcode that we want to execute in the victim, and inject it along with a shellcode defining the instructions to find that “egg” in memory. Once the "egg" is found, execution is passed to the shellcode after the "egg". 

### Requirements of the Egg Hunter Shellcode 
---
The Egg Hunter Shellcode will have to search in the Virtual Address Space for the "egg". As searching in the VAS is a dangerous process, an Egg Hunter Shellcode must have the following requirements: 

- It must be robust. The Egg Hunter must be able to do searches anywhere in memory, also in invalid regions, without crashing 
- Must be small as the Egg Hunter payload must fit into very small amount of memory. Considering it’s size is very important  
- The Egg Hunter code must be fast to avoid iddle times during the search of the "egg" in memory 

### Egg Hunter Implementation
---
In the paper, the autor mentions diferent techniques to search in memory using the `access()` system call. This is the solution that is going to be implemented. 

Some considerations to have in mind: 

- With the `access()` syscall, instead of using a pathname to the function parameter, a memory address can be used to check if that memory position has been allocated. If it’s not allocated, the syscall will return an **EFAULT** error code. If this is the case, there is no need to search on this memory address, as is not allocated for the process. The call requires two parameters: (1) The `pathname`, that's the memory position to check, and (2) `mode`, that will be **F_OK**, just to check if the position is there. 
```c
int access (const char * pathname, int mode); 
```
- Memory positions are agrupated into pages. This makes the search in memory with the `access()` syscall shorter, as if the syscall tries to access a position of memory not allocated, the whole page where this memory position belongs to, won’t be accesible. Hence, only is needed to check one memory position for each memory page.  

- To reduce false positives in the “egg” search, “egg” needs to be repeated twice. For example, a false positive could be the Egg Hunter shellcode finding itself as contains the “egg”. For that, a 4 bytes “egg” used twice is used.

All this said, the Egg Hunter Shellcode has to do the following: 
- Check memory pages if they are accesible 
- If the memory page is accessible, then search on each memory position of that page for the “egg” 
- If the egg is found in memory, check next memory position if also has the egg (egg is 2 consecutive memory positions) 
- If both eggs found, then jump to execute the shellcode that will be after the two eggs 

The summarized pseudocode will be: 
```markdown
while (remain memory pages to check){ 
  if ( memory_page_is_accessible(first_memory_position_of_the_page) ) { 
    i = 0; 
    if (memory_position[i] == “EGG”) { 
        if (memory_position[i+1] == “EGG”) { 
            EGG_FOUND; 
            JMP_to_run(memory_position[i+2]; 
        } 
    } else { 
      i++; 
    } 
  } else { 
    go_to_check_next_memory_page; 
  } 
} 
```
### ASM Implementation
---









### The End
---
This pages have been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: PA-14628
 
