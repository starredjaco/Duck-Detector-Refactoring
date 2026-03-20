#pragma once

#include <string>
#include <vector>

namespace systemproperties {

    struct ReadOnlyPropertySerialFinding {
        std::string property;
        int suspicious_sample_count = 0;
        std::string low24_hex;
        std::string detail;
    };

    struct ReadOnlyPropertySerialSnapshot {
        bool available = false;
        int checked_count = 0;
        int finding_count = 0;
        std::vector<ReadOnlyPropertySerialFinding> findings;
    };

    ReadOnlyPropertySerialSnapshot
    scan_readonly_property_serials(const std::vector<std::string> &properties);

}  // namespace systemproperties
