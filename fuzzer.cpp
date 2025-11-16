// Build example (adjust include/lib paths as needed):
//   afl-clang-fast++ -g -O2 \
//       -I/usr/include/unicorn -I/usr/include/unicornafl \
//       fuzzer.cpp -lunicorn -lunicornafl -o fuzzer
// Run with AFL++ (unicorn mode):
//   AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
//   afl-fuzz -U -i in -o out -m none -- ./fuzzer modem.bin

#include <unicorn/unicorn.h>
#include <unicornafl/unicornafl.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>


#define FUNC_ADDR       0x40EE90A6     // start of UndefinedFunction_40ee90a6
#define FUN_40BFF0B6 (0x40BFF0B6 | 1)

// Memory & fuzz layout
constexpr uint32_t CODE_BASE      = 0x40000000;
constexpr uint32_t CODE_SIZE      = 0x04000000;   // 64 MB

constexpr uint32_t RAM_START      = 0x04000000;
constexpr uint32_t RAM_SIZE       = 0x01000000;   // 16 MB

constexpr uint32_t INPUT_ADDR     = 0x20000000;
constexpr uint32_t INPUT_SIZE     = 0x2000;


constexpr uint32_t EXIT_ADDR      = RAM_START;    

static uc_engine* uc = nullptr;

static void die(const char* msg, uc_err err = UC_ERR_OK) {
    if (err != UC_ERR_OK) {
        std::fprintf(stderr, "%s: %s\n", msg, uc_strerror(err));
    } else {
        std::fprintf(stderr, "%s\n", msg);
    }
    std::exit(1);
}

// FUN_40BFF0B6 so it returns fuzz buffer pointer
static void hook_stub_alloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)address;
    (void)size;
    (void)user_data;

    uint32_t ret = INPUT_ADDR;
    uc_err err = uc_reg_write(uc, UC_ARM_REG_R0, &ret);
    if (err != UC_ERR_OK) {
        die("hook_stub_alloc: uc_reg_write R0 failed", err);
    }

    // Simulate a normal function return: PC = LR
    uint32_t lr = 0;
    err = uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    if (err != UC_ERR_OK) {
        die("hook_stub_alloc: uc_reg_read LR failed", err);
    }

    err = uc_reg_write(uc, UC_ARM_REG_PC, &lr);
    if (err != UC_ERR_OK) {
        die("hook_stub_alloc: uc_reg_write PC failed", err);
    }
}

bool setup_memory() {
    uc_err err;

    err = uc_mem_map(uc, CODE_BASE, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        die("uc_mem_map CODE_BASE failed", err);
    }

    err = uc_mem_map(uc, RAM_START, RAM_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        die("uc_mem_map RAM_START failed", err);
    }

    err = uc_mem_map(uc, INPUT_ADDR, INPUT_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        die("uc_mem_map INPUT_ADDR failed", err);
    }

    // Blank RAM
    std::vector<uint8_t> mem(RAM_SIZE, 0);
    err = uc_mem_write(uc, RAM_START, mem.data(), RAM_SIZE);
    if (err != UC_ERR_OK) {
        die("uc_mem_write RAM_START failed", err);
    }

    return true;
}

bool load_firmware(const char* fw) {
    std::ifstream f(fw, std::ios::binary);
    if (!f.is_open()) {
        std::perror("open firmware");
        return false;
    }

    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());

    if (bytes.empty()) {
        std::fprintf(stderr, "Firmware file is empty\n");
        return false;
    }

    if (bytes.size() > CODE_SIZE) {
        std::fprintf(stderr, "Firmware too large: %zu > %u\n",
                     bytes.size(), CODE_SIZE);
        return false;
    }

    uc_err err = uc_mem_write(uc, CODE_BASE, bytes.data(), bytes.size());
    if (err != UC_ERR_OK) {
        die("uc_mem_write firmware failed", err);
    }

    return true;
}

// AFL++ callback: copy current test case into the fuzz buffer
extern "C" bool place_input_callback(uc_engine* uc, char* data, size_t data_len,
                                     unsigned int, void*) {
    if (data_len > INPUT_SIZE) {
        data_len = INPUT_SIZE;
    }

    uc_err err = uc_mem_write(uc, INPUT_ADDR, data, data_len);
    if (err != UC_ERR_OK) {
        std::fprintf(stderr, "place_input_callback: uc_mem_write failed: %s\n",
                     uc_strerror(err));
        return false;
    }
    return true;
}

// AFL++ crash validation: return true to count every unicorn error as a crash
extern "C" bool validate_crash_callback(uc_engine* uc, uc_err unicorn_result,
                                        char*, int, int, void*) {
    (void)uc;
    (void)unicorn_result;
    
    return true;
}

static void setup_cpu_state() {
    uc_err err;

    // Stack pointer near top of RAM
    uint32_t sp = RAM_START + RAM_SIZE - 0x1000;
    err = uc_reg_write(uc, UC_ARM_REG_SP, &sp);
    if (err != UC_ERR_OK) {
        die("uc_reg_write SP failed", err);
    }

    // Program counter at target function
    uint32_t pc = FUNC_ADDR;
    err = uc_reg_write(uc, UC_ARM_REG_PC, &pc);
    if (err != UC_ERR_OK) {
        die("uc_reg_write PC failed", err);
    }

    // Safe return address inside mapped memory.
    uint32_t lr = EXIT_ADDR;
    err = uc_reg_write(uc, UC_ARM_REG_LR, &lr);
    if (err != UC_ERR_OK) {
        die("uc_reg_write LR failed", err);
    }

    uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
    uint32_t r4 = 0, r7 = 0, r8 = 0, r9 = INPUT_ADDR;

    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R1, &r1);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);
    uc_reg_write(uc, UC_ARM_REG_R4, &r4);
    uc_reg_write(uc, UC_ARM_REG_R7, &r7);
    uc_reg_write(uc, UC_ARM_REG_R8, &r8);
    uc_reg_write(uc, UC_ARM_REG_R9, &r9);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s firmware.bin\n", argv[0]);
        return 1;
    }

    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    uint32_t pc = FUNC_ADDR | 1; // Set Thumb bit

    // If your code is Thumb, use:
    // err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err != UC_ERR_OK) {
        die("uc_open failed", err);
    }

    if (!setup_memory()) {
        die("Memory setup failed");
    }

    if (!load_firmware(argv[1])) {
        die("Firmware load failed");
    }

    
    uc_hook h_alloc;
    err = uc_hook_add(uc, &h_alloc, UC_HOOK_CODE,
                      (void*)hook_stub_alloc, nullptr,
                      FUN_40BFF0B6, FUN_40BFF0B6);
    if (err != UC_ERR_OK) {
        die("uc_hook_add for FUN_40BFF0B6 failed", err);
    }

    setup_cpu_state();

    char* seed = (char*)"seed_input";

    std::printf("[*] Fuzzing Shannon function @ 0x%08X\n", FUNC_ADDR);

    uint64_t exits[] = { EXIT_ADDR };

    // Reasonable instruction cap to avoid infinite loops
    const uint64_t max_instructions = 5'000'000;

    while (true) {
        
        uint64_t exits[] = {}; 

    // Lower instruction cap for finite loop
    const uint64_t max_instructions = 500000; // 500k inst

    uc_afl_ret afl_ret = uc_afl_fuzz(
        uc,
        seed,
        place_input_callback,
        exits, 0,           
        validate_crash_callback,
        true,
        max_instructions,
        nullptr
    );
         switch (afl_ret) {
            case UC_AFL_RET_OK:
                // Normal successful exit (rare with AFL)
                std::fprintf(stderr, "uc_afl_fuzz: OK, exiting.\n");
                uc_close(uc);
                return 0;
            case UC_AFL_RET_FINISHED:
                
                std::fprintf(stderr, "uc_afl_fuzz: FINISHED.\n");
                uc_close(uc);
                return 0;

            case UC_AFL_RET_LIBAFL:       
                std::fprintf(stderr, "uc_afl_fuzz: LIBAFL bootstrap detected (%d) — doing local run.\n", afl_ret);

                setup_cpu_state();
                place_input_callback(uc, seed, std::strlen(seed), 0, nullptr);

                err = uc_emu_start(uc, FUNC_ADDR, EXIT_ADDR, 0, max_instructions);
                if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) {
                    die("uc_emu_start during LIBAFL bootstrap failed", err);
                } 
                continue;
            case UC_AFL_RET_ERROR:
            default:
                std::fprintf(stderr, "uc_afl_fuzz returned error: %d\n", afl_ret);
                uc_close(uc);
                return 1;
        }

    }
}
