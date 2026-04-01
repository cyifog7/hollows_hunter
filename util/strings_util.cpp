#include "strings_util.h"

#include <algorithm>
#include <cstring>

std::string hhunter::util::to_lowercase(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}

bool hhunter::util::is_cstr_equal(char const *a, char const *b, const size_t max_len)
{
    for (size_t i = 0; i < max_len; ++i) {
        if (tolower(a[i]) != tolower(b[i])) {
            return false;
        }
        if (tolower(a[i]) == '\0') break;
    }
    return true;
}

size_t hhunter::util::levenshtein_distance(const char s1[], const char s2[])
{
    const size_t MAX_LEN = 100;
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);

    if (len1 >= MAX_LEN || len2 >= MAX_LEN) return static_cast<size_t>(-1);

    int row_a[MAX_LEN + 1] = { 0 };
    int row_b[MAX_LEN + 1] = { 0 };
    int* prev = row_a;
    int* curr = row_b;

    for (size_t i = 0; i <= len2; i++) {
        prev[i] = static_cast<int>(i);
    }

    for (size_t j = 1; j <= len1; j++) {
        curr[0] = static_cast<int>(j);
        for (size_t i = 1; i <= len2; i++) {
            int cost = (s1[j - 1] == s2[i - 1]) ? 0 : 1;
            int del_cost = prev[i] + 1;
            int ins_cost = curr[i - 1] + 1;
            int sub_cost = prev[i - 1] + cost;
            curr[i] = (std::min)({del_cost, ins_cost, sub_cost});
        }
        std::swap(prev, curr);
    }
    return static_cast<size_t>(prev[len2]);
}

size_t hhunter::util::str_hist_diffrence(const char s1[], const char s2[])
{
    const size_t MAX_LEN = 255;
    size_t hist1[MAX_LEN] = { 0 };
    size_t hist2[MAX_LEN] = { 0 };

    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);

    for (size_t i = 0; i < len1; i++) {
        unsigned char c = static_cast<unsigned char>(tolower(s1[i]));
        hist1[c]++;
    }

    for (size_t i = 0; i < len2; i++) {
        unsigned char c = static_cast<unsigned char>(tolower(s2[i]));
        hist2[c]++;
    }

    size_t diffs = 0;
    for (size_t i = 0; i < MAX_LEN; i++) {
        if (hist2[i] == hist1[i]) continue;
        diffs++;
    }
    return diffs;
}

hhunter::util::stringsim_type hhunter::util::is_string_similar(const std::string &param, const std::string &filter)
{
    bool sim_found = (param.find(filter) != std::string::npos) || (filter.find(param) != std::string::npos);
    if (sim_found) return SIM_SUBSTR;

    size_t dist = util::levenshtein_distance(filter.c_str(), param.c_str());
    if (dist <= (param.length() / 2)) {
        sim_found = true;
    }
    if (dist >= param.length() || dist >= filter.length()) {
        sim_found = false;
    }
    if (sim_found) return SIM_LAV_DIST;

    size_t diff = util::str_hist_diffrence(filter.c_str(), param.c_str());
    if (diff <= (param.length() / 2) || diff <= (filter.length() / 2)) {
        sim_found = true;
    }
    if (diff >= param.length() || diff >= filter.length()) {
        sim_found = false;
    }
    if (sim_found) return SIM_HIST;
    return SIM_NONE;
}
