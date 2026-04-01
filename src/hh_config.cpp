#include "hh_config.h"

#include <windows.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

static std::string trim(std::string s)
{
    const char* ws = " \t\r\n";
    size_t start = s.find_first_not_of(ws);
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

static std::wstring to_wstr(const std::string& s)
{
    return std::wstring(s.begin(), s.end());
}

std::string get_config_path()
{
    char path[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string exePath(path);
    size_t pos = exePath.find_last_of("\\/");
    if (pos != std::string::npos) {
        exePath = exePath.substr(0, pos + 1);
    }
    return exePath + "hollows_hunter.ini";
}

bool load_config(const std::string& ini_path, t_hh_params& params)
{
    std::ifstream f(ini_path);
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line)) {
        size_t comment = line.find_first_of(";#");
        if (comment != std::string::npos) line.resize(comment);

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key.empty() || val.empty()) continue;

        std::transform(key.begin(), key.end(), key.begin(), ::tolower);

        if (key == "vt_api_key") {
            params.vt_api_key = val;
        }
        else if (key == "vt_ignore") {
            std::istringstream ss(val);
            std::string token;
            while (std::getline(ss, token, ';')) {
                token = trim(token);
                if (!token.empty()) params.vt_ignore_list.insert(to_wstr(token));
            }
        }
        else if (key == "pignore") {
            std::istringstream ss(val);
            std::string token;
            while (std::getline(ss, token, ';')) {
                token = trim(token);
                if (!token.empty()) params.ignored_names_list.insert(to_wstr(token));
            }
        }
        else if (key == "dir") {
            params.out_dir = val;
        }
        else if (key == "quiet") {
            params.quiet = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "log") {
            params.log = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "json") {
            params.json_output = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "loop") {
            params.loop_scanning = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "unique_dir") {
            params.unique_dir = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "hooks") {
            if (val == "1" || val == "true" || val == "True") {
                params.pesieve_args.no_hooks = false;
            }
        }
        else if (key == "suspend") {
            params.suspend_suspicious = (val == "1" || val == "true" || val == "True");
        }
        else if (key == "kill") {
            params.kill_suspicious = (val == "1" || val == "true" || val == "True");
        }
    }
    f.close();
    return true;
}

bool save_default_config(const std::string& ini_path)
{
    std::ifstream check(ini_path);
    if (check.is_open()) {
        check.close();
        return false;
    }

    std::ofstream f(ini_path);
    if (!f.is_open()) return false;

    f << "; HollowsHunter configuration\n";
    f << "; CLI arguments override these values\n";
    f << "\n";
    f << "; Skip VT lookups for these processes (separated by ;)\n";
    f << "vt_ignore=AnyDesk.exe\n";
    f << "\n";
    f << "; Ignore these processes from scanning (separated by ;)\n";
    f << "pignore=\n";
    f << "\n";
    f << "; Output directory\n";
    f << "dir=hollows_hunter.dumps\n";
    f << "\n";
    f << "; Options: true/false\n";
    f << "quiet=false\n";
    f << "log=false\n";
    f << "json=false\n";
    f << "loop=false\n";
    f << "unique_dir=false\n";
    f << "hooks=false\n";
    f << "suspend=false\n";
    f << "kill=false\n";

    f.close();
    return true;
}
