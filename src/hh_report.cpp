#include "hh_report.h"

#include <string>
#include <sstream>
#include <codecvt>
#include <locale>
#include <iostream>
#include <iomanip>
#include <cmath>

#include "util/time_util.h"

#define OUT_PADDED(stream, field_size, str) \
std::cout.fill(' '); \
if (field_size) stream << std::setw(field_size) << ' '; \
stream << str;


bool HHScanReport::appendReport(pesieve::t_report &scan_report, const std::wstring &img_name)
{
    pidToReport[scan_report.pid] = scan_report;
    pidToName[scan_report.pid] = img_name;
    if (scan_report.suspicious) {
        this->suspicious.push_back(scan_report.pid);
    }
    if (scan_report.errors == pesieve::ERROR_SCAN_FAILURE) {
        this->failed.push_back(scan_report.pid);
    }
    return true;
}

size_t HHScanReport::reportsToString(std::wstringstream& stream, const pesieve::t_results_filter rfilter) const
{
    if (rfilter == pesieve::SHOW_NONE) {
        return 0;
    }
    size_t printed = 0;
    size_t counter = 0;
    size_t scannedCount = countReports(rfilter);

    if (!scannedCount) {
        return printed;
    }

    const size_t max_len = size_t(std::floor(std::log10(double(scannedCount))) + 1) % 100;
    for (const auto& [pid, rep] : this->pidToReport) {
        bool isFailed = false;
        if ((rfilter & pesieve::SHOW_SUSPICIOUS) == 0) {
            if (rep.suspicious) continue;
        }
        if ((rfilter & pesieve::SHOW_NOT_SUSPICIOUS) == 0) {
            if (!rep.suspicious) continue;
        }
        if (rep.errors == pesieve::ERROR_SCAN_FAILURE) {
            isFailed = true;
        }

        if (isFailed && ((rfilter & pesieve::SHOW_ERRORS) == 0)) {
            continue; // do not display failed
        }
        stream << L"[" << std::setw(max_len) << counter++ << L"]: PID: " << std::dec << pid << L", ";
        auto nameIt = this->pidToName.find(pid);
        if (nameIt != this->pidToName.end()) {
            stream << L"Name: " << nameIt->second;
        }
        if (isFailed) {
            stream << L" : FAILED";
        }
        auto vtIt = this->pidToVT.find(pid);
        if (vtIt != this->pidToVT.end() && vtIt->second.found) {
            const auto& vtRes = vtIt->second;
            stream << L" [VT: " << vtRes.positives << L"/" << vtRes.total;
            if (!vtRes.threat_label.empty()) {
                std::wstring wlabel(vtRes.threat_label.begin(), vtRes.threat_label.end());
                stream << L" " << wlabel;
            }
            stream << L"]";
        }
        stream << L"\n";
        printed++;
    }
    return printed;
}

size_t HHScanReport::reportsToJSON(std::wstringstream &stream, size_t level, const t_hh_params &params) const
{
    OUT_PADDED(stream, level, L"\"suspicious\" : [\n");
    level++;
    size_t printed = 0;
    for (const auto& pid : this->suspicious) {
        auto repIt = pidToReport.find(pid);
        if (repIt == pidToReport.end()) continue;
        const auto& rep = repIt->second;

        auto nameIt = pidToName.find(pid);
        const std::wstring& name = (nameIt != pidToName.end()) ? nameIt->second : L"";

        OUT_PADDED(stream, level, L"{\n");
        level++;

        OUT_PADDED(stream, level, L"\"pid\" : ");
        stream << std::dec << pid << L",\n";
        OUT_PADDED(stream, level, L"\"is_managed\" : ");
        stream << std::dec << rep.is_managed << L",\n";
        OUT_PADDED(stream, level, L"\"name\" : ");
        stream << L"\"" << name << L"\",\n";
        OUT_PADDED(stream, level, L"\"replaced\" : ");
        stream << std::dec << rep.replaced << L",\n";
        OUT_PADDED(stream, level, L"\"hdr_modified\" : ");
        stream << std::dec << rep.hdr_mod << L",\n";
        if (!params.pesieve_args.no_hooks) {
            OUT_PADDED(stream, level, L"\"patched\" : ");
            stream << std::dec << rep.patched << L",\n";
        }
        if (params.pesieve_args.iat != pesieve::PE_IATS_NONE) {
            OUT_PADDED(stream, level, L"\"iat_hooked\" : ");
            stream << std::dec << rep.iat_hooked << L",\n";
        }
        OUT_PADDED(stream, level, L"\"implanted_pe\" : ");
        stream << std::dec << rep.implanted_pe << L",\n";
        OUT_PADDED(stream, level, L"\"implanted_shc\" : ");
        stream << std::dec << rep.implanted_shc << L",\n";
        OUT_PADDED(stream, level, L"\"unreachable_file\" : ");
        stream << std::dec << rep.unreachable_file << L",\n";
        OUT_PADDED(stream, level, L"\"other\" : ");
        stream << std::dec << rep.other;

        auto vtIt = pidToVT.find(pid);
        if (vtIt != pidToVT.end() && vtIt->second.found) {
            const auto& vtRes = vtIt->second;
            stream << L",\n";
            OUT_PADDED(stream, level, L"\"virustotal\" : {\n");
            level++;
            OUT_PADDED(stream, level, L"\"score\" : \"");
            stream << vtRes.positives << L"/" << vtRes.total << L"\",\n";
            OUT_PADDED(stream, level, L"\"threat_label\" : \"");
            std::wstring wlabel(vtRes.threat_label.begin(), vtRes.threat_label.end());
            stream << wlabel << L"\",\n";
            OUT_PADDED(stream, level, L"\"sha256\" : \"");
            std::wstring whash(vtRes.sha256.begin(), vtRes.sha256.end());
            stream << whash << L"\",\n";
            OUT_PADDED(stream, level, L"\"permalink\" : \"");
            std::wstring wlink(vtRes.permalink.begin(), vtRes.permalink.end());
            stream << wlink << L"\"\n";
            level--;
            OUT_PADDED(stream, level, L"}");
        }
        stream << L"\n";
        level--;
        OUT_PADDED(stream, level, L"}");
        printed++;
        if (printed < suspicious.size()) {
            stream << L",";
        }
        stream << L"\n";
    }
    level--;
    OUT_PADDED(stream, level, L"]\n");
    return printed;
}

size_t HHScanReport::toJSON(std::wstringstream &stream, const t_hh_params &params) const
{
    size_t level = 0;
    OUT_PADDED(stream, level, L"{\n");
    level++;
    //summary:
    const size_t suspicious_count = countReports(pesieve::SHOW_SUSPICIOUS);
    size_t all_count = 0;
    OUT_PADDED(stream, level, L"\"scan_date_time\" : ");
    stream << std::dec << L"\"" << util::strtime(this->startTime) << L"\"" << L",\n";
    OUT_PADDED(stream, level, L"\"scan_timestamp\" : ");
    stream << std::dec << startTime << L",\n";
    OUT_PADDED(stream, level, L"\"scan_time_ms\" : ");
    stream << std::dec << getScanTime() << L",\n";
    OUT_PADDED(stream, level, L"\"scanned_count\" : ");
    stream << std::dec << countTotal(true) << L",\n";
    OUT_PADDED(stream, level, L"\"failed_count\" : ");
    stream << std::dec << countReports(pesieve::SHOW_ERRORS) << L",\n";
    OUT_PADDED(stream, level, L"\"suspicious_count\" : ");
    stream << std::dec << suspicious_count;
    if (suspicious_count > 0) {
        stream << L",\n";
        all_count = reportsToJSON(stream, level, params);
    }
    else {
        stream << L"\n";
    }
    level--;
    OUT_PADDED(stream, level, L"}\n");
    return all_count;
}

template<class STR_STREAM>
void print_scantime(STR_STREAM& stream, size_t timeInMs)
{
    float seconds = ((float)timeInMs / 1000);
    float minutes = ((float)timeInMs / 60000);
    stream << std::dec << timeInMs << L" ms.";
    if (seconds > 0.5) {
        stream << L" = " << seconds << L" sec.";
    }
    if (minutes > 0.5) {
        stream << L" = " << minutes << L" min.";
    }
}

void HHScanReport::toString(std::wstringstream &stream, const pesieve::t_results_filter rfilter) const
{
    //summary:
    stream << L"--------" << std::endl;
    stream << L"SUMMARY:\n";
    stream << L"Scan at: " << util::strtime(this->startTime) << L" (" << std::dec << startTime << L")\n";
    stream << L"Finished scan in: ";
    print_scantime(stream, getScanTime());
    stream << L"\n";
    const size_t scannedCount = countReports(pesieve::SHOW_SUCCESSFUL_ONLY);
    stream << L"[*] Total scanned: " << std::dec << scannedCount << L"\n";
    if ((rfilter & pesieve::SHOW_NOT_SUSPICIOUS) && scannedCount > 0) {
        stream << L"[+] List of scanned: \n";
        reportsToString(stream, pesieve::SHOW_SUCCESSFUL_ONLY);
    }
    if (rfilter & pesieve::SHOW_SUSPICIOUS) {
        const size_t count = countReports(pesieve::SHOW_SUSPICIOUS);
        stream << L"[*] Total suspicious: " << std::dec << count << L"\n";
        if (count > 0) {
            stream << L"[+] List of suspicious: \n";
            reportsToString(stream, pesieve::SHOW_SUSPICIOUS);
        }
    }
    if (rfilter & pesieve::SHOW_ERRORS) {
        const size_t count = countReports(pesieve::SHOW_ERRORS);
        stream << L"[*] Total failed: " << std::dec << count << L"\n";
    }
}
