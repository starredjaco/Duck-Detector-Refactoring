#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_CGROUP_PROCESS_PROBE_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_CGROUP_PROCESS_PROBE_H

#include <string>
#include <vector>

namespace duckdetector::nativeroot {

    struct CgroupLeakPathEntry {
        std::string path;
        int uid = -1;
        bool accessible = false;
        int pid_count = 0;
    };

    struct CgroupLeakProcessEntry {
        std::string uid_path;
        int cgroup_uid = -1;
        int pid = -1;
        int proc_uid = -1;
        long long starttime_ticks = -1;
        int kill_errno = -1;
        int getsid_value = -1;
        int getsid_errno = -1;
        int getpgid_value = -1;
        int getpgid_errno = -1;
        int sched_policy = -1;
        int sched_errno = -1;
        int pidfd_errno = -1;
        std::string proc_context;
        std::string comm;
        std::string cmdline;
    };

    struct CgroupLeakSnapshot {
        bool available = false;
        int path_check_count = 0;
        int accessible_path_count = 0;
        int process_count = 0;
        int proc_denied_count = 0;
        std::vector<CgroupLeakPathEntry> paths;
        std::vector<CgroupLeakProcessEntry> entries;
    };

    CgroupLeakSnapshot collect_cgroup_leak_snapshot();

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_CGROUP_PROCESS_PROBE_H
