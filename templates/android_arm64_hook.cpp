// Explicit, offline patch primitives for memory owned by the calling application.
// No injector, automatic hook, or architecture translation is provided.
// Android NDK, arm64-v8a/API 24 example (join the two lines into one command):
//   $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++
//     -std=c++17 -fPIC -shared -fno-exceptions -fno-rtti -nostdlib++ android_arm64_hook.cpp -o liboffline_patch.so
// The absolute jump is a 16-byte branch stub, NOT a complete trampoline: it
// clobbers X17, and does not save or relocate displaced PC-relative instructions.
// Never substitute PS4/x86 bytes for independently verified Android ARM64 bytes.
// Stop all threads which might use the page; ensure it is readable, mapped,
// uniformly protected, and does not contain this patcher's currently executing code.
// Some Android kernels/policies reject permission changes. No operation is atomic.
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Return: 0 success; -1 invalid arguments; -2 expected bytes differ;
// -3 mprotect for writing failed; -4 bytes changed but restoring protection failed.
extern "C" int apply_offline_patch(void* address, const unsigned char* expected,
                                   const unsigned char* replacement, size_t size,
                                   int original_prot) {
    if (!address || !expected || !replacement || size == 0 ||
        !(original_prot & PROT_READ)) return -1;
    const long page_size_raw = sysconf(_SC_PAGESIZE);
    if (page_size_raw <= 0) return -1;
    const uintptr_t page_size = static_cast<uintptr_t>(page_size_raw);
    const uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    if (size > UINTPTR_MAX - addr || addr + size > UINTPTR_MAX - (page_size - 1)) return -1;
    const uintptr_t start = addr - addr % page_size;
    const uintptr_t end_unaligned = addr + size;
    const uintptr_t end = (end_unaligned + page_size - 1) / page_size * page_size;
    const size_t span = static_cast<size_t>(end - start);
    if (memcmp(address, expected, size) != 0) return -2;
#if defined(OFFLINE_PATCH_ALLOW_RWX)
    // Opt-in only: RWX can violate platform policy and weakens W^X isolation.
    const int writable = original_prot | PROT_READ | PROT_WRITE | PROT_EXEC;
#else
    // Safer default: temporarily remove execute while writing. Stop other threads.
    const int writable = (original_prot | PROT_READ | PROT_WRITE) & ~PROT_EXEC;
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, writable) != 0) return -3;
    memcpy(address, replacement, size);
#if defined(__GNUC__) || defined(__clang__)
    char* first = static_cast<char*>(address);
    __builtin___clear_cache(first, first + size);
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, original_prot) != 0) return -4;
    return 0;
}

// Emit little-endian: LDR X17, #8; BR X17; destination (64 bits).
// The caller owns output[0..15]. This encoder alone does not touch code pages.
extern "C" int encode_arm64_absolute_jump(unsigned char* output, size_t capacity,
                                          uint64_t destination) {
    if (!output || capacity < 16) return -1;
    const uint32_t words[2] = {0x58000051u, 0xD61F0220u};
    for (size_t i = 0; i < 2; ++i) {
        for (size_t byte = 0; byte < 4; ++byte)
            output[i * 4 + byte] = static_cast<unsigned char>(words[i] >> (byte * 8));
    }
    for (size_t byte = 0; byte < 8; ++byte)
        output[8 + byte] = static_cast<unsigned char>(destination >> (byte * 8));
    return 0;
}

// Caller must separately check the entire overwritten 16-byte ARM64 instruction
// sequence and provide an aligned, valid destination in the SAME process.
extern "C" int apply_offline_arm64_jump(void* address, const unsigned char* expected,
                                        uint64_t destination, int original_prot) {
    if (!address || !expected || !destination ||
        (reinterpret_cast<uintptr_t>(address) & 3u) || (destination & 3u)) return -1;
    unsigned char jump[16];
    if (encode_arm64_absolute_jump(jump, sizeof(jump), destination) != 0) return -1;
    return apply_offline_patch(address, expected, jump, sizeof(jump), original_prot);
}

#if defined(OFFLINE_PATCH_ENABLE_CONSTRUCTOR)
// Explicit opt-in initialization point. Intentionally does NOT discover targets
// or patch anything automatically; integrate it into your own application only.
__attribute__((constructor)) static void offline_patch_initialize() {
}
#endif
