#pragma once

#include <string>
#include <map>

namespace vt {

    struct VTResult {
        bool found = false;
        bool error = false;
        int positives = 0;
        int total = 0;
        std::string threat_label;
        std::string sha256;
        std::string permalink;
        std::string error_msg;

        std::string scoreStr() const {
            if (error) return "error";
            if (!found) return "not found";
            return std::to_string(positives) + "/" + std::to_string(total);
        }
    };

    std::string sha256_file(const std::string& file_path);
    VTResult lookup_hash(const std::string& api_key, const std::string& sha256);
    bool write_vt_report(const std::string& output_path, const VTResult& result);

}
