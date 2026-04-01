#define WIN32_LEAN_AND_MEAN

#ifndef _WIN64
#undef USE_ETW //ETW support works only for 64 bit
#endif //_WIN64

#if (_MSC_VER < 1900)
#undef USE_ETW //ETW not supported
#endif

#include <iostream>
#include <string>

#include "color_scheme.h"
#include "hh_scanner.h"

#include <pe_sieve_types.h>
#include <pe_sieve_return_codes.h>

#include "params_info/params.h"

#include "util/process_privilege.h"
#include "util/strings_util.h"
#include "hh_ver_short.h"
#include "hh_global.h"
#include "hh_config.h"

using namespace hhunter::util;

t_hh_params hhunter::g_hh_args;

#ifdef USE_ETW
#include "etw_listener.h"
#endif

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

t_pesieve_res deploy_scan()
{
    t_pesieve_res scan_res = PESIEVE_NOT_DETECTED;
    hhunter::util::set_debug_privilege();
    if (hhunter::g_hh_args.pesieve_args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE && hhunter::g_hh_args.pesieve_args.make_reflection == false) {
        print_in_color(RED, "[WARNING] Scanning of inaccessible pages is enabled only in the reflection mode!\n");
    }
    if (hhunter::g_hh_args.etw_scan)
    {
#ifdef USE_ETW
        const char profileIni[] = "HH_ETWProfile.ini";
        ETWProfile profile;
        profile.initProfile(profileIni);
        if (!profile.isEnabled()) {
            std::cerr << "Cannot start ETW: the profile (\"" << profileIni << "\") is empty\n";
            return PESIEVE_ERROR;
        }
        std::cout << "ETWProfile defined by:\"" << profileIni << "\"\n";
        if (!ETWstart(profile)) {
            return PESIEVE_ERROR;
        }
#else
        std::cerr << "ETW support is disabled\n";
        return PESIEVE_ERROR;
#endif
    }
    else
    {
        HHScanner scanner(hhunter::g_hh_args);
        do {
            auto report = scanner.scan();
            if (report) {
                scanner.summarizeScan(*report, hhunter::g_hh_args.pesieve_args.results_filter);
                if (report->countReports(pesieve::SHOW_SUSPICIOUS) > 0) {
                    scan_res = PESIEVE_DETECTED;
                }
            }
            if (!HHScanner::isScannerCompatibile()) {
                compatibility_alert();
            }
        } while (hhunter::g_hh_args.loop_scanning);
    }
    return scan_res;
}

bool is_running_as_admin()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

int main(int argc, char *argv[])
{
    if (!is_running_as_admin()) {
        print_in_color(RED, "[ERROR] This tool requires Administrator privileges. Please run as Administrator.\n");
        return PESIEVE_ERROR;
    }

    hhunter::g_hh_args.init();

    std::string ini_path = get_config_path();
    save_default_config(ini_path);
    load_config(ini_path, hhunter::g_hh_args);

    bool info_req = false;
    HHParams uParams(HH_VERSION_STR);
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(hhunter::g_hh_args);

    if (hhunter::g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || hhunter::g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
        if (!hhunter::g_hh_args.pesieve_args.make_reflection) {
            hhunter::g_hh_args.pesieve_args.make_reflection = true;
            print_in_color(RED, "[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!\n");
        }
    }

    print_version(HH_VERSION_STR);
    std::cout << std::endl;
    if (argc < 2) {
        print_in_color(WHITE, "Default scan deployed.");
        std::cout << std::endl;
    }
    const t_pesieve_res  res = deploy_scan();
    uParams.freeStruct(hhunter::g_hh_args);
    return res;
}
