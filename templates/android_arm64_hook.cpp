// Offline patch primitive for code owned/controlled by the calling application.
// No injector, automatic hook, or platform/architecture translation is provided.
// Compile with the Android NDK, for example:
//   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++
//     -std=c++17 -fPIC -shared android_arm64_hook.cpp -o liboffline_patch.so
// (join those two lines into one shell command)
// The application must call apply_offline_patch itself, with verified ARM64 bytes
// and a separately resolved address. Never substitute x86-64 GoldHEN bytes.
// Stop all threads that might execute/read the page and ensure the entire range
// is readable, mapped, has uniform original_prot, and remains mapped throughout.
// Some Android kernels/policies forbid changing executable-page permissions.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

// Return: 0 success; -1 invalid arguments; -2 expected bytes differ;
// -3 mprotect for writing failed; -4 bytes changed but restoring protection failed.
extern "C" int apply_offline_patch(void* address, const unsigned char* expected,
                                   const unsigned char* replacement, std::size_t size,
                                   int original_prot) {
    if (!address || !expected || !replacement || size == 0 ||
        !(original_prot & PROT_READ)) return -1;
    const long page_size_raw = sysconf(_SC_PAGESIZE);
    if (page_size_raw <= 0) return -1;
    const auto page_size = static_cast<std::uintptr_t>(page_size_raw);
    const auto addr = reinterpret_cast<std::uintptr_t>(address);
    const auto max = std::numeric_limits<std::uintptr_t>::max();
    if (size > max - addr || addr + size > max - (page_size - 1)) return -1;
    const auto start = addr - addr % page_size;
    const auto end_unaligned = addr + size;
    const auto end = (end_unaligned + page_size - 1) / page_size * page_size;
    const auto span = static_cast<std::size_t>(end - start);
    // The caller guarantees the memory is readable before this comparison.
    if (std::memcmp(address, expected, size) != 0) return -2;
    // W^X: temporarily remove execute while writing. Threads must be stopped.
    const int writable = (original_prot | PROT_READ | PROT_WRITE) & ~PROT_EXEC;
    if (mprotect(reinterpret_cast<void*>(start), span, writable) != 0) return -3;
    std::memcpy(address, replacement, size);
#if defined(__GNUC__) || defined(__clang__)
    auto* first = static_cast<char*>(address);
    __builtin___clear_cache(first, first + size);
#endif
    if (mprotect(reinterpret_cast<void*>(start), span, original_prot) != 0) return -4;
    return 0;
}
