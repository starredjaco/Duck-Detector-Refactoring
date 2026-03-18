#include "tee/keystore/environment_probe.h"

#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <string>

#include <sys/syscall.h>
#include <unistd.h>

#include "tee/common/syscall_facade.h"

namespace ducktee::keystore {
    namespace {

        bool read_tracer_pid() {
            FILE *file = std::fopen("/proc/self/status", "r");
            if (file == nullptr) {
                return false;
            }

            char line[256];
            bool traced = false;
            while (std::fgets(line, sizeof(line), file) != nullptr) {
                if (std::strncmp(line, "TracerPid:", 10) == 0) {
                    traced = std::atoi(line + 10) != 0;
                    break;
                }
            }
            std::fclose(file);
            return traced;
        }

        std::vector<std::string> collect_suspicious_mappings() {
            std::vector<std::string> matches;
            FILE *file = std::fopen("/proc/self/maps", "r");
            if (file == nullptr) {
                return matches;
            }

            constexpr std::array<const char *, 5> kKeywords = {
                    "tricky",
                    "tee_sim",
                    "keybox",
                    "keystore_interceptor",
                    "bootloader_spoofer",
            };

            char line[512];
            while (std::fgets(line, sizeof(line), file) != nullptr) {
                std::string value(line);
                for (const char *keyword: kKeywords) {
                    if (value.find(keyword) != std::string::npos) {
                        value.erase(value.find_last_not_of("\r\n") + 1);
                        matches.push_back(value);
                        break;
                    }
                }
            }
            std::fclose(file);
            return matches;
        }

        std::string measure_timing_summary() {
            constexpr int kIterations = 12;
            constexpr int kAttempts = 3;
            std::array<long long, kAttempts> clock_averages{};
            std::array<long long, kAttempts> syscall_averages{};

            for (int attempt = 0; attempt < kAttempts; ++attempt) {
                long long clock_total = 0;
                long long syscall_total = 0;
                for (int i = 0; i < kIterations; ++i) {
                    const auto start_clock = std::chrono::steady_clock::now();
                    (void) std::chrono::steady_clock::now();
                    const auto end_clock = std::chrono::steady_clock::now();
                    clock_total += std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_clock - start_clock).count();

                    const auto start_syscall = std::chrono::steady_clock::now();
                    (void) ducktee::common::raw_syscall3(__NR_getpid, 0, 0, 0);
                    const auto end_syscall = std::chrono::steady_clock::now();
                    syscall_total += std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_syscall - start_syscall).count();
                }
                clock_averages[attempt] = clock_total / kIterations;
                syscall_averages[attempt] = syscall_total / kIterations;
            }

            const auto clock_minmax =
                    std::minmax_element(clock_averages.begin(), clock_averages.end());
            const auto syscall_minmax =
                    std::minmax_element(syscall_averages.begin(), syscall_averages.end());

            std::ostringstream builder;
            builder << "clock_ns=" << *clock_minmax.first << "-" << *clock_minmax.second
                    << ", syscall_ns=" << *syscall_minmax.first << "-" << *syscall_minmax.second
                    << ", attempts=" << kAttempts;
            return builder.str();
        }

    }  // namespace

    EnvironmentSnapshot collect_environment() {
        EnvironmentSnapshot snapshot;
        snapshot.tracing_detected = read_tracer_pid();
        snapshot.page_size = static_cast<int>(::sysconf(_SC_PAGESIZE));
        snapshot.timing_summary = measure_timing_summary();
        snapshot.suspicious_mappings = collect_suspicious_mappings();
        return snapshot;
    }

}  // namespace ducktee::keystore
