#include "nativeroot/probes/cgroup_process_probe.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        struct linux_dirent64 {
            std::uint64_t d_ino;
            std::int64_t d_off;
            unsigned short d_reclen;
            unsigned char d_type;
            char d_name[];
        };

        constexpr const char *kUidPathPatterns[] = {
                "/sys/fs/cgroup/uid_%d",
                "/sys/fs/cgroup/apps/uid_%d",
                "/sys/fs/cgroup/system/uid_%d",
                "/dev/cg2_bpf/uid_%d",
                "/dev/cg2_bpf/apps/uid_%d",
                "/dev/cg2_bpf/system/uid_%d",
                "/acct/uid_%d",
                "/dev/memcg/apps/uid_%d",
        };

        std::vector<int> candidate_uids() {
            std::set<int> values = {0, 1000, 2000, static_cast<int>(getuid())};
            return {values.begin(), values.end()};
        }

        std::vector<std::pair<std::string, int>> candidate_uid_paths() {
            std::vector<std::pair<std::string, int>> paths;
            for (const int uid: candidate_uids()) {
                for (const char *pattern: kUidPathPatterns) {
                    char buffer[256];
                    std::snprintf(buffer, sizeof(buffer), pattern, uid);
                    paths.emplace_back(buffer, uid);
                }
            }
            return paths;
        }

        int parse_pid_dir(const char *name, const size_t max_length) {
            constexpr char kPrefix[] = "pid_";
            if (name == nullptr) {
                return -1;
            }
            if (std::strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) {
                return -1;
            }

            const char *pid_chars = name + sizeof(kPrefix) - 1;
            if (*pid_chars == '\0') {
                return -1;
            }
            if (!is_numeric_name(pid_chars,
                                 max_length >= sizeof(kPrefix) ? max_length - (sizeof(kPrefix) - 1)
                                                               : 0)) {
                return -1;
            }
            return std::atoi(pid_chars);
        }

        std::string read_bytes_file(const char *path, const size_t max_size) {
            const int fd = syscall_openat_readonly(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return "";
            }

            std::string content;
            content.resize(max_size);
            const ssize_t bytes_read = syscall_read_fd(fd, content.data(), max_size);
            syscall_close_fd(fd);

            if (bytes_read <= 0) {
                return "";
            }

            content.resize(static_cast<size_t>(bytes_read));
            return content;
        }

        int parse_status_uid(const std::string &status_text) {
            if (status_text.empty()) {
                return -1;
            }

            const std::string key = "\nUid:";
            const size_t key_pos = status_text.find(key);
            const size_t start = key_pos == std::string::npos ? 0 : key_pos + 1;
            const size_t line_end = status_text.find('\n', start);
            const std::string line = trim_copy(status_text.substr(start, line_end - start));
            if (line.rfind("Uid:", 0) != 0) {
                return -1;
            }
            const std::string ids = trim_copy(line.substr(4));
            const size_t space = ids.find_first_of(" \t");
            return std::atoi(ids.substr(0, space).c_str());
        }

        std::string read_proc_text(int pid, const char *suffix, size_t max_size) {
            char buffer[256];
            std::snprintf(buffer, sizeof(buffer), "/proc/%d/%s", pid, suffix);
            return read_bytes_file(buffer, max_size);
        }

        std::string read_proc_line(int pid, const char *suffix, size_t max_size) {
            return trim_copy(read_proc_text(pid, suffix, max_size));
        }

    }  // namespace

    CgroupLeakSnapshot collect_cgroup_leak_snapshot() {
        CgroupLeakSnapshot snapshot;
        std::set<std::string> dedupe;

        const auto uid_paths = candidate_uid_paths();
        snapshot.path_check_count = static_cast<int>(uid_paths.size());

        for (const auto &[uid_path, uid]: uid_paths) {
            CgroupLeakPathEntry path_entry{
                    .path = uid_path,
                    .uid = uid,
            };

            const int uid_fd = syscall_openat_readonly(uid_path.c_str(),
                                                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (uid_fd < 0) {
                snapshot.paths.push_back(path_entry);
                continue;
            }

            snapshot.available = true;
            path_entry.accessible = true;
            snapshot.accessible_path_count += 1;

            char dent_buffer[4096];
            while (true) {
                const int bytes_read = syscall_getdents64_fd(uid_fd, dent_buffer,
                                                             sizeof(dent_buffer));
                if (bytes_read <= 0) {
                    break;
                }

                int offset = 0;
                while (offset < bytes_read) {
                    if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                        break;
                    }

                    auto *entry = reinterpret_cast<linux_dirent64 *>(dent_buffer + offset);
                    if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                        break;
                    }

                    const size_t max_name_length =
                            entry->d_reclen - offsetof(linux_dirent64, d_name);
                    const bool dir_like =
                            entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN;
                    const int pid = dir_like ? parse_pid_dir(entry->d_name, max_name_length) : -1;
                    if (pid > 0) {
                        path_entry.pid_count += 1;
                        snapshot.process_count += 1;

                        const std::string status_text = read_proc_text(pid, "status", 4096);
                        const std::string comm = read_proc_line(pid, "comm", 256);
                        const std::string cmdline = read_proc_text(pid, "cmdline", 512);
                        if (status_text.empty()) {
                            snapshot.proc_denied_count += 1;
                        }

                        const std::string dedupe_key = uid_path + "|" + std::to_string(pid);
                        if (dedupe.insert(dedupe_key).second) {
                            snapshot.entries.push_back(
                                    CgroupLeakProcessEntry{
                                            .uid_path = uid_path,
                                            .cgroup_uid = uid,
                                            .pid = pid,
                                            .proc_uid = parse_status_uid(status_text),
                                            .comm = comm,
                                            .cmdline = cmdline,
                                    }
                            );
                        }
                    }

                    offset += entry->d_reclen;
                }
            }

            syscall_close_fd(uid_fd);
            snapshot.paths.push_back(path_entry);
        }

        return snapshot;
    }

}  // namespace duckdetector::nativeroot
