#ifndef DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H
#define DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H

#include "memory/common/types.h"

#include <optional>
#include <string>
#include <vector>

namespace duckdetector::memory {

    std::vector<MapEntry> read_self_maps();

    std::vector<SmapsEntry> read_self_smaps();

    std::optional<MapEntry> find_entry_for_address(
            const std::vector<MapEntry> &maps,
            std::uintptr_t address
    );

    bool is_system_path(const std::string &path);

    bool is_benign_art_code_cache_path(const std::string &path);

    bool is_probably_jit_path(const std::string &path);

    bool is_suspicious_loader_path(const std::string &path);

    bool is_benign_loader_artifact_path(const std::string &path);

    bool is_anonymous_path(const std::string &path);

    std::string basename_of(const std::string &path);

    std::string to_lower_ascii(std::string value);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H
