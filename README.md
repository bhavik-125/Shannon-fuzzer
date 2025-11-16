Shannon Baseband Function Fuzzer

This repository contains a standalone fuzzing harness targeting a function inside a Shannon baseband firmware image.
It uses Unicorn Engine for ARM/Thumb emulation and AFL++ for coverage-guided fuzzing.

Files:

-fuzzer (compiled harness)
-fuzzer.cpp (source code)
-modem.zip (contains modem.bin)
-in.zip (AFL seed corpus)

Requirements:
- AFL++
- Unicorn Engine (ARM)
- unicornafl
- C++17 compiler
- python3-dev (only if UnicornAFL was built with Python)

Install example (Ubuntu):

```bash
sudo apt install afl++ unicorn-dev python3-dev
```

Build steps:
Extract modem.zip → you should have modem.bin

Compile using this command:

```bash
afl-clang-fast++ -g -O2 -I/usr/include/unicorn -I/usr/include/unicornafl fuzzer.cpp -L/usr/lib/x86_64-linux-gnu -lunicorn -lunicornafl -lpython3.12 -o fuzzer
```

(If needed, change python3.12 to python3.10 or python3.11 depending on your system)

Running the fuzzer:

```bash
Extract in.zip → this creates the "in" folder
```
Run AFL++ with this command:

```bash
AFL_FAST_CAL=1 AFL_AUTORESUME=1 afl-fuzz -U -t 2000 -i in -o out -m none -- ./fuzzer modem.bin
```
Explanation:
-U → Unicorn mode
-t 2000 → timeout 2 seconds
-m none → no memory limit
Persistent mode is enabled in the harness

Crash outputs:
Crashes are automatically stored in:

```bash
out/default/crashes/
```
Example crash file:
id:000007,sig:11,src:000002,op:havoc

To replay a crash:

```bash
./fuzzer modem.bin < crashfile
```

Optional: generate more seeds:
(for example, 50 random buffers)

```bash
for i in $(seq 0 50); do head -c $((RANDOM % 64 + 1)) /dev/urandom > in/seed_$i; done
```
How the fuzzer works:
- Maps firmware at address `0x40000000`
- Jumps to target function at `0x40EE90A6` (Thumb mode)
- Hooks allocator to return fuzz buffer
- Writes mutated input to `0x20000000`
- Uses Unicorn instruction limit to stop execution
- Treats invalid reads, writes, or instruction fetches as crashes
