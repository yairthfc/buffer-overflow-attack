# Stack-Based Buffer Overflow Exploit (x64 Linux)

## Project Overview
This project demonstrates a classic **Stack-Based Buffer Overflow** attack targeting a vulnerable TCP server running on x64 Linux. 

The goal was to engineer a custom client in C that exploits a vulnerability in the server's input handling (specifically a `recv` function missing boundary checks). By crafting a precise malicious payload, I successfully overwrote the Return Instruction Pointer (RIP), hijacked the control flow, and injected custom shellcode to execute a remote script (`/tmp/success_script`) with specific arguments.

## Key Technical Concepts
* **Low-Level Memory Manipulation:** Manual stack navigation and memory layout calculation.
* **x64 Assembly (AT&T Syntax):** Writing and injecting raw machine code (Shellcode) to invoke system calls (`sys_execve`).
* **Network Programming:** Implementing raw TCP sockets in C to deliver the payload.
* **Exploit Development:** calculating offsets, handling Endianness (Little Endian vs. Big Endian), and managing memory alignment.

## The Vulnerability
The target server was running a process vulnerable to buffer overflow. [cite_start]It lacked standard modern protections (compiled with `-fno-stack-protector`, executable stack enabled via `mprotect`, and ASLR effectively bypassed via address leaking)[cite: 267, 268, 269].

This allowed for a direct attack where the stack could be flooded with data to overwrite the saved return address.

## Exploit Architecture
My solution (`ex1.c`) functions as an exploit builder and delivery system.

### 1. Payload Construction
Unlike simple static payloads, this exploit dynamically calculates memory addresses at runtime based on the stack address leaked by the server. The payload is structured as follows:

| Section | Description |
| :--- | :--- |
| **Padding** | Garbage data ('A's) to fill the buffer up to the saved RIP. |
| **New RIP** | The address of the immediate next instruction (pointing to the Shellcode). |
| **Shellcode** | x64 machine code that invokes `execve`. |
| **Data Segment** | The path string, Student ID string, and the `argv` array pointers required by `execve`. |

### 2. Shellcode Logic
I implemented a custom shellcode template in raw hex bytes. The C program patches this template at runtime to include the exact addresses of the strings located further down in the stack.

The assembly logic (AT&T syntax) performs the following:
1.  **`mov $59, %rax`**: Prepares the `sys_execve` system call number.
2.  **`movabs PATH, %rdi`**: Loads the address of the script path into the first argument register.
3.  **`movabs ARGV, %rsi`**: Loads the address of the argument array into the second argument register.
4.  **`xor %rdx, %rdx`**: Clears the third argument (Environment pointer is NULL).
5.  **`syscall`**: Triggers the kernel to execute the process.

### 3. Delivery
[cite_start]The program establishes a standard `AF_INET` `SOCK_STREAM` connection to the target (IP: `192.168.1.202`, Port: `12345`) and sends the calculated binary payload[cite: 171, 172].

## Usage

### Compilation
The exploit is compiled using `gcc` with strict warning flags to ensure memory safety within the attack code itself.

```bash
gcc -Wall -Wextra -Werror -Wconversion ex1.c -o attacker
