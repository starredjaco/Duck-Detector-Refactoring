#include "tee/trickystore/trickystore_probe.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "tee/common/syscall_facade.h"

namespace ducktee::trickystore {
    namespace {

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)

        struct binder_write_read {
            signed long write_size;
            signed long write_consumed;
            unsigned long write_buffer;
            signed long read_size;
            signed long read_consumed;
            unsigned long read_buffer;
        };

        struct binder_version {
            signed long protocol_version;
        };

        struct binder_transaction_data {
            union {
                unsigned int handle;
                void *ptr;
            } target;
            void *cookie;
            unsigned int code;
            unsigned int flags;
            int sender_pid;
            unsigned int sender_euid;
            unsigned long data_size;
            unsigned long offsets_size;
            union {
                struct {
                    unsigned long buffer;
                    unsigned long offsets;
                } ptr;
                unsigned char buf[8];
            } data;
        };

        struct MethodSnapshot {
            bool detected = false;
            std::string detail;
            std::vector<std::string> findings;
        };

        struct LibInfo {
            uintptr_t base = 0;
            std::string path;
            bool found = false;
        };

        struct MapAccess {
            bool found = false;
            bool readable = false;
        };

        constexpr int kHoneypotIterations = 40;
        constexpr std::uint64_t kHoneypotThresholdNs = 10'000ULL;
        constexpr int kRepeatedProbeAttempts = 3;

        int raw_open(const char *path, int flags) {
#if defined(__NR_openat)
            return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
#else
            return open(path, flags);
#endif
        }

        int open_binder_device() {
            int fd = raw_open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                fd = raw_open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
            }
            return fd;
        }

        std::uint64_t now_ns() {
            timespec ts{};
            clock_gettime(CLOCK_MONOTONIC, &ts);
            return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
                   static_cast<std::uint64_t>(ts.tv_nsec);
        }

        LibInfo find_library(const std::string &needle) {
            LibInfo info;
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return info;
            }

            std::string line;
            while (std::getline(maps, line)) {
                if (line.find(needle) == std::string::npos) {
                    continue;
                }
                const std::size_t dash = line.find('-');
                if (dash == std::string::npos) {
                    continue;
                }

                uintptr_t address = 0;
                for (std::size_t index = 0; index < dash; ++index) {
                    const char ch = line[index];
                    address <<= 4;
                    if (ch >= '0' && ch <= '9') {
                        address |= static_cast<uintptr_t>(ch - '0');
                    } else if (ch >= 'a' && ch <= 'f') {
                        address |= static_cast<uintptr_t>(ch - 'a' + 10);
                    } else if (ch >= 'A' && ch <= 'F') {
                        address |= static_cast<uintptr_t>(ch - 'A' + 10);
                    }
                }

                const std::size_t path_start = line.find('/');
                if (path_start == std::string::npos) {
                    continue;
                }

                info.base = address;
                info.path = line.substr(path_start);
                while (!info.path.empty() && info.path.back() <= ' ') {
                    info.path.pop_back();
                }
                info.found = true;
                break;
            }
            return info;
        }

        MapAccess find_map_access_for_address(const uintptr_t address) {
            MapAccess access;
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return access;
            }

            std::string line;
            while (std::getline(maps, line)) {
                unsigned long long start = 0;
                unsigned long long end = 0;
                char perms[5] = {};
                if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end, perms) != 3) {
                    continue;
                }
                if (address < start || address >= end) {
                    continue;
                }
                access.found = true;
                access.readable = perms[0] == 'r';
                return access;
            }
            return access;
        }

        bool maps_contain_trickystore(std::vector<std::string> *findings) {
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return false;
            }

            bool matched = false;
            std::string line;
            while (std::getline(maps, line)) {
                if (line.find("tricky") != std::string::npos ||
                    line.find("keystore_interceptor") != std::string::npos) {
                    matched = true;
                    if (findings != nullptr) {
                        findings->push_back(line);
                    }
                }
            }
            return matched;
        }

#if defined(__LP64__)
        using ElfWord_Ehdr = Elf64_Ehdr;
        using ElfWord_Phdr = Elf64_Phdr;
        using ElfWord_Dyn = Elf64_Dyn;
        using ElfWord_Sym = Elf64_Sym;
        using ElfWord_Rela = Elf64_Rela;
        using ElfWord_Addr = Elf64_Addr;
#define DUCK_ELF_R_SYM(value) ELF64_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF64_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#if defined(__x86_64__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#endif
#else
        using ElfWord_Ehdr = Elf32_Ehdr;
        using ElfWord_Phdr = Elf32_Phdr;
        using ElfWord_Dyn = Elf32_Dyn;
        using ElfWord_Sym = Elf32_Sym;
        using ElfWord_Rela = Elf32_Rel;
        using ElfWord_Addr = Elf32_Addr;
#define DUCK_ELF_R_SYM(value) ELF32_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF32_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_ARM_JUMP_SLOT
#if defined(__i386__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_386_JMP_SLOT
#endif
#endif

        MethodSnapshot detect_got_ioctl_hook() {
            MethodSnapshot snapshot;

            void *real_ioctl = dlsym(RTLD_DEFAULT, "ioctl");
            if (real_ioctl == nullptr) {
                snapshot.detail = "Failed to resolve ioctl via dlsym.";
                return snapshot;
            }

            const LibInfo binder = find_library("libbinder.so");
            if (!binder.found || binder.path.empty()) {
                snapshot.detail = "libbinder.so not found in process maps.";
                return snapshot;
            }

            const int fd = raw_open(binder.path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                snapshot.detail = "Failed to open libbinder.so for GOT inspection.";
                return snapshot;
            }

            ElfWord_Ehdr ehdr{};
            if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
                std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
                close(fd);
                snapshot.detail = "Failed to read a valid ELF header from libbinder.so.";
                return snapshot;
            }

            std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
            lseek(fd, ehdr.e_phoff, SEEK_SET);
            const auto phdr_bytes = sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
            if (read(fd, phdrs.data(), phdr_bytes) != static_cast<ssize_t>(phdr_bytes)) {
                close(fd);
                snapshot.detail = "Failed to read libbinder.so program headers.";
                return snapshot;
            }
            close(fd);

            ElfWord_Addr dyn_vaddr = 0;
            for (const auto &phdr: phdrs) {
                if (phdr.p_type == PT_DYNAMIC) {
                    dyn_vaddr = phdr.p_vaddr;
                    break;
                }
            }
            if (dyn_vaddr == 0) {
                snapshot.detail = "PT_DYNAMIC segment missing from libbinder.so.";
                return snapshot;
            }

            auto *dyn_base = reinterpret_cast<ElfWord_Dyn *>(binder.base + dyn_vaddr);
            ElfWord_Addr jmprel = 0;
            ElfWord_Addr pltrelsz = 0;
            ElfWord_Addr symtab_addr = 0;
            ElfWord_Addr strtab_addr = 0;

            for (auto *dyn = dyn_base; dyn->d_tag != DT_NULL; ++dyn) {
                switch (dyn->d_tag) {
                    case DT_JMPREL:
                        jmprel = dyn->d_un.d_ptr;
                        break;
                    case DT_PLTRELSZ:
                        pltrelsz = dyn->d_un.d_val;
                        break;
                    case DT_SYMTAB:
                        symtab_addr = dyn->d_un.d_ptr;
                        break;
                    case DT_STRTAB:
                        strtab_addr = dyn->d_un.d_ptr;
                        break;
                    default:
                        break;
                }
            }

            if (jmprel != 0 && jmprel < binder.base) {
                jmprel += binder.base;
            }
            if (symtab_addr != 0 && symtab_addr < binder.base) {
                symtab_addr += binder.base;
            }
            if (strtab_addr != 0 && strtab_addr < binder.base) {
                strtab_addr += binder.base;
            }

            if (jmprel == 0 || pltrelsz == 0 || symtab_addr == 0 || strtab_addr == 0) {
                snapshot.detail = "libbinder.so was missing PLT relocation metadata for ioctl.";
                return snapshot;
            }

            auto *rels = reinterpret_cast<ElfWord_Rela *>(jmprel);
            auto *symtab = reinterpret_cast<ElfWord_Sym *>(symtab_addr);
            auto *strtab = reinterpret_cast<const char *>(strtab_addr);
            const std::size_t rel_count = pltrelsz / sizeof(ElfWord_Rela);

            for (std::size_t index = 0; index < rel_count; ++index) {
                const unsigned long sym_index = DUCK_ELF_R_SYM(rels[index].r_info);
                const unsigned long rel_type = DUCK_ELF_R_TYPE(rels[index].r_info);
                if (rel_type != DUCK_R_JUMP_SLOT) {
                    continue;
                }

                const char *symbol_name = strtab + symtab[sym_index].st_name;
                if (std::strcmp(symbol_name, "ioctl") != 0) {
                    continue;
                }

                auto *got_entry = reinterpret_cast<void **>(binder.base + rels[index].r_offset);
                void *got_value = *got_entry;
                if (got_value != real_ioctl) {
                    snapshot.detected = true;
                    Dl_info dl_info{};
                    std::string hook_library = "unknown";
                    if (dladdr(got_value, &dl_info) && dl_info.dli_fname != nullptr) {
                        hook_library = dl_info.dli_fname;
                    }
                    std::ostringstream builder;
                    builder << "libbinder.so ioctl GOT entry resolved to " << got_value
                            << " instead of libc ioctl " << real_ioctl
                            << " (hook library: " << hook_library << ").";
                    snapshot.findings.push_back(builder.str());
                    snapshot.detail = "GOT hook detected on ioctl in libbinder.so.";
                } else {
                    snapshot.detail = "libbinder.so ioctl GOT entry matched libc.";
                }
                return snapshot;
            }

            snapshot.detail = "ioctl relocation was not found in libbinder.so.";
            return snapshot;
        }

        MethodSnapshot run_single_syscall_ioctl_mismatch_probe() {
            MethodSnapshot snapshot;
            const int binder_fd = open_binder_device();
            if (binder_fd < 0) {
                snapshot.detail = "Cannot open binder device for ioctl comparison.";
                return snapshot;
            }

            binder_version raw_version{};
            binder_version libc_version{};
            errno = 0;
            const long raw_result = ducktee::common::raw_ioctl(binder_fd, BINDER_VERSION,
                                                               &raw_version);
            const int raw_errno = errno;
            errno = 0;
            const int libc_result = ioctl(binder_fd, BINDER_VERSION, &libc_version);
            const int libc_errno = errno;
            close(binder_fd);

            if (raw_result != libc_result ||
                raw_errno != libc_errno ||
                raw_version.protocol_version != libc_version.protocol_version) {
                snapshot.detected = true;
                std::ostringstream builder;
                builder << "raw ioctl result=" << raw_result
                        << " errno=" << raw_errno
                        << " version=" << raw_version.protocol_version
                        << " differed from libc ioctl result=" << libc_result
                        << " errno=" << libc_errno
                        << " version=" << libc_version.protocol_version << ".";
                snapshot.findings.push_back(builder.str());
                snapshot.detail = "Raw ioctl and libc ioctl returned different binder results.";
            } else {
                snapshot.detail = "Raw ioctl and libc ioctl matched on binder version query.";
            }
            return snapshot;
        }

        MethodSnapshot detect_syscall_ioctl_mismatch() {
            MethodSnapshot snapshot;
            int hit_count = 0;
            std::string last_detail;

            for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
                const MethodSnapshot single = run_single_syscall_ioctl_mismatch_probe();
                if (!single.detail.empty()) {
                    last_detail = single.detail;
                }
                if (!single.detected) {
                    continue;
                }
                ++hit_count;
                if (snapshot.findings.empty()) {
                    snapshot.findings = single.findings;
                }
            }

            snapshot.detected = hit_count >= 2;
            std::ostringstream builder;
            if (snapshot.detected) {
                builder << "Raw ioctl and libc ioctl diverged on " << hit_count
                        << "/" << kRepeatedProbeAttempts << " binder version probes.";
                snapshot.detail = builder.str();
            } else {
                builder << "Raw ioctl and libc ioctl stayed aligned across "
                        << kRepeatedProbeAttempts << " binder version probes";
                if (hit_count > 0) {
                    builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                            << " suspicious run).";
                } else {
                    builder << ".";
                }
                if (!last_detail.empty()) {
                    builder << " " << last_detail;
                }
                snapshot.detail = builder.str();
            }
            return snapshot;
        }

        MethodSnapshot detect_ioctl_inline_hook() {
            MethodSnapshot snapshot;

            void *ioctl_addr = dlsym(RTLD_DEFAULT, "ioctl");
            if (ioctl_addr == nullptr) {
                snapshot.detail = "Failed to resolve ioctl for inline hook inspection.";
                return snapshot;
            }

            Dl_info ioctl_info{};
            if (!dladdr(ioctl_addr, &ioctl_info) || ioctl_info.dli_fname == nullptr) {
                snapshot.detail = "Failed to resolve the backing library for ioctl.";
                return snapshot;
            }

            const MapAccess ioctl_map =
                    find_map_access_for_address(reinterpret_cast<uintptr_t>(ioctl_addr));
            if (!ioctl_map.found || !ioctl_map.readable) {
                snapshot.detail =
                        "Skipped ioctl inline hook inspection because the resolved code page is not readable.";
                return snapshot;
            }

            std::uint8_t memory_prologue[16];
            std::memcpy(memory_prologue, ioctl_addr, sizeof(memory_prologue));

            const LibInfo lib_info = find_library(ioctl_info.dli_fname);
            if (!lib_info.found) {
                snapshot.detail = "Could not locate ioctl library in process maps.";
                return snapshot;
            }

            const int fd = raw_open(ioctl_info.dli_fname, O_RDONLY | O_CLOEXEC);
            bool compared_on_disk = false;
            if (fd >= 0) {
                ElfWord_Ehdr ehdr{};
                if (read(fd, &ehdr, sizeof(ehdr)) == sizeof(ehdr) &&
                    std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
                    std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
                    lseek(fd, ehdr.e_phoff, SEEK_SET);
                    const auto phdr_bytes =
                            sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
                    if (read(fd, phdrs.data(), phdr_bytes) == static_cast<ssize_t>(phdr_bytes)) {
                        const uintptr_t ioctl_va =
                                reinterpret_cast<uintptr_t>(ioctl_addr) - lib_info.base;
                        for (const auto &phdr: phdrs) {
                            if (phdr.p_type != PT_LOAD) {
                                continue;
                            }
                            if (ioctl_va >= phdr.p_vaddr &&
                                ioctl_va < phdr.p_vaddr + phdr.p_filesz) {
                                const uintptr_t file_offset =
                                        phdr.p_offset + (ioctl_va - phdr.p_vaddr);
                                std::uint8_t disk_prologue[16];
                                lseek(fd, static_cast<off_t>(file_offset), SEEK_SET);
                                if (read(fd, disk_prologue, sizeof(disk_prologue)) ==
                                    sizeof(disk_prologue)) {
                                    compared_on_disk = true;
                                    if (!ducktee::common::bytes_equal(memory_prologue,
                                                                      disk_prologue,
                                                                      sizeof(memory_prologue))) {
                                        snapshot.detected = true;
                                        std::ostringstream builder;
                                        builder
                                                << "In-memory ioctl prologue differed from the on-disk image.";
                                        snapshot.findings.push_back(builder.str());
                                        snapshot.detail = "Inline hook detected on ioctl.";
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                close(fd);
            }

#if defined(__aarch64__)
            if (!snapshot.detected) {
                auto* instructions = reinterpret_cast<const std::uint32_t*>(ioctl_addr);
                for (int index = 0; index < 4; ++index) {
                    const std::uint32_t word = instructions[index];
                    if ((word & 0xFC000000U) == 0x14000000U && index == 0) {
                        const std::int32_t imm26 = static_cast<std::int32_t>(word << 6) >> 6;
                        const uintptr_t target = reinterpret_cast<uintptr_t>(&instructions[index]) + static_cast<uintptr_t>(imm26 * 4);
                        Dl_info target_info{};
                        if (dladdr(reinterpret_cast<void*>(target), &target_info) &&
                            target_info.dli_fname != nullptr &&
                            std::string(target_info.dli_fname) != std::string(ioctl_info.dli_fname)) {
                            snapshot.detected = true;
                            snapshot.findings.push_back("ioctl begins with an unconditional branch into another library.");
                            snapshot.detail = "Inline hook detected via external branch trampoline.";
                            break;
                        }
                    }
                    if ((word & 0xFFFFFC1FU) == 0xD61F0000U && index < 2) {
                        snapshot.detected = true;
                        snapshot.findings.push_back("ioctl prologue contained a BR register jump.");
                        snapshot.detail = "Inline hook detected via BR trampoline.";
                        break;
                    }
                }
            }
#endif

            if (!snapshot.detected) {
                snapshot.detail = compared_on_disk
                                  ? "ioctl prologue matched the on-disk image."
                                  : "Could not compare the ioctl prologue with the on-disk image.";
            }
            return snapshot;
        }

        MethodSnapshot run_single_ioctl_honeypot_probe() {
            MethodSnapshot snapshot;
            const int binder_fd = open_binder_device();
            if (binder_fd < 0) {
                snapshot.detail = "Cannot open binder device for honeypot timing.";
                return snapshot;
            }

            void *mapped = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, binder_fd, 0);
            if (mapped == MAP_FAILED) {
                close(binder_fd);
                snapshot.detail = "Cannot mmap binder device for honeypot timing.";
                return snapshot;
            }

            std::uint8_t write_buffer[256];
            std::memset(write_buffer, 0, sizeof(write_buffer));
            const std::uint32_t command = BC_TRANSACTION;
            std::memcpy(write_buffer, &command, sizeof(command));

            binder_transaction_data transaction{};
            transaction.target.handle = 0;
            transaction.code = 1;
            transaction.data_size = 64;
            transaction.offsets_size = 0;

            std::uint8_t fake_data[64];
            std::memset(fake_data, 0, sizeof(fake_data));
            const char *descriptor = "android.security.keystore2";
            std::memcpy(fake_data, descriptor, std::strlen(descriptor));
            transaction.data.ptr.buffer = reinterpret_cast<unsigned long>(fake_data);
            transaction.data.ptr.offsets = 0;

            std::memcpy(write_buffer + sizeof(command), &transaction, sizeof(transaction));

            binder_write_read bwr{};
            bwr.write_buffer = reinterpret_cast<unsigned long>(write_buffer);
            bwr.write_size = sizeof(command) + sizeof(transaction);

            std::uint64_t got_total = 0;
            for (int index = 0; index < kHoneypotIterations; ++index) {
                bwr.write_consumed = 0;
                const std::uint64_t start = now_ns();
                ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
                got_total += now_ns() - start;
            }

            std::uint64_t raw_total = 0;
            for (int index = 0; index < kHoneypotIterations; ++index) {
                bwr.write_consumed = 0;
                const std::uint64_t start = now_ns();
                ducktee::common::raw_ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
                raw_total += now_ns() - start;
            }

            munmap(mapped, 4096);
            close(binder_fd);

            const std::uint64_t got_average = got_total / kHoneypotIterations;
            const std::uint64_t raw_average = raw_total / kHoneypotIterations;
            if (got_average > raw_average && (got_average - raw_average) > kHoneypotThresholdNs) {
                snapshot.detected = true;
                std::ostringstream builder;
                builder << "GOT ioctl averaged " << got_average
                        << "ns while raw ioctl averaged " << raw_average
                        << "ns on a keystore2-like binder transaction.";
                snapshot.findings.push_back(builder.str());
                snapshot.detail = "Keystore-style binder honeypot triggered a timing anomaly.";
            } else {
                snapshot.detail = "Keystore-style binder honeypot timing stayed within normal bounds.";
            }
            return snapshot;
        }

        MethodSnapshot detect_ioctl_honeypot() {
            MethodSnapshot snapshot;
            int hit_count = 0;
            std::string last_detail;

            for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
                const MethodSnapshot single = run_single_ioctl_honeypot_probe();
                if (!single.detail.empty()) {
                    last_detail = single.detail;
                }
                if (!single.detected) {
                    continue;
                }
                ++hit_count;
                if (snapshot.findings.empty()) {
                    snapshot.findings = single.findings;
                }
            }

            snapshot.detected = hit_count >= 2;
            std::ostringstream builder;
            if (snapshot.detected) {
                builder << "Keystore-style binder honeypot triggered on " << hit_count
                        << "/" << kRepeatedProbeAttempts << " timing runs.";
                snapshot.detail = builder.str();
            } else {
                builder << "Keystore-style binder honeypot stayed within normal bounds across "
                        << kRepeatedProbeAttempts << " runs";
                if (hit_count > 0) {
                    builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                            << " suspicious run).";
                } else {
                    builder << ".";
                }
                if (!last_detail.empty()) {
                    builder << " " << last_detail;
                }
                snapshot.detail = builder.str();
            }
            return snapshot;
        }

    }  // namespace

    ProbeSnapshot inspect_process() {
        ProbeSnapshot snapshot;
        std::vector<std::string> methods;
        std::vector<std::string> findings;

        std::vector<std::string> map_hits;
        if (maps_contain_trickystore(&map_hits)) {
            snapshot.detected = true;
            methods.push_back("MAPS_NAME_HIT");
            if (!map_hits.empty()) {
                findings.push_back("Suspicious process map entry: " + map_hits.front());
            }
        }

        const MethodSnapshot got_result = detect_got_ioctl_hook();
        if (got_result.detected) {
            snapshot.detected = true;
            snapshot.got_hook_detected = true;
            methods.push_back("GOT_HOOK");
            findings.insert(findings.end(), got_result.findings.begin(), got_result.findings.end());
        }

        const MethodSnapshot syscall_result = detect_syscall_ioctl_mismatch();
        if (syscall_result.detected) {
            snapshot.syscall_mismatch_detected = true;
            methods.push_back("SYSCALL_MISMATCH");
            findings.insert(findings.end(), syscall_result.findings.begin(),
                            syscall_result.findings.end());
        }

        const MethodSnapshot inline_result = detect_ioctl_inline_hook();
        if (inline_result.detected) {
            snapshot.detected = true;
            snapshot.inline_hook_detected = true;
            methods.push_back("INLINE_HOOK");
            findings.insert(findings.end(), inline_result.findings.begin(),
                            inline_result.findings.end());
        }

        const MethodSnapshot honeypot_result = detect_ioctl_honeypot();
        if (honeypot_result.detected) {
            snapshot.detected = true;
            snapshot.honeypot_detected = true;
            methods.push_back("HONEYPOT");
            findings.insert(findings.end(), honeypot_result.findings.begin(),
                            honeypot_result.findings.end());
        }

        snapshot.methods = methods;
        if (!findings.empty()) {
            std::ostringstream builder;
            builder << "methods=";
            for (std::size_t index = 0; index < methods.size(); ++index) {
                if (index > 0) {
                    builder << ",";
                }
                builder << methods[index];
            }
            builder << " | " << findings.front();
            snapshot.details = builder.str();
        } else if (snapshot.syscall_mismatch_detected) {
            snapshot.details = syscall_result.detail;
        } else {
            std::ostringstream builder;
            builder << got_result.detail
                    << " | " << inline_result.detail
                    << " | " << honeypot_result.detail;
            snapshot.details = builder.str();
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore
