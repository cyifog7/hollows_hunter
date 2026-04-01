#include "vt_lookup.h"

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <deque>
#include <mutex>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

static void vt_throttle()
{
    static std::mutex mtx;
    static std::deque<std::chrono::steady_clock::time_point> timestamps;
    const int MAX_REQUESTS = 4;
    const auto WINDOW = std::chrono::seconds(60);

    std::lock_guard<std::mutex> lock(mtx);
    auto now = std::chrono::steady_clock::now();

    while (!timestamps.empty() && (now - timestamps.front()) > WINDOW) {
        timestamps.pop_front();
    }

    if (timestamps.size() >= MAX_REQUESTS) {
        auto wait_until = timestamps.front() + WINDOW;
        auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(wait_until - now).count();
        if (wait_ms > 0) {
            Sleep(static_cast<DWORD>(wait_ms));
        }
        now = std::chrono::steady_clock::now();
        while (!timestamps.empty() && (now - timestamps.front()) > WINDOW) {
            timestamps.pop_front();
        }
    }

    timestamps.push_back(now);
}

std::string vt::sha256_file(const std::string& file_path)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return result;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return result;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    char buf[4096];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        DWORD bytesRead = static_cast<DWORD>(file.gcount());
        if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(buf), bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return result;
        }
        if (file.eof()) break;
    }

    DWORD hashLen = 32;
    BYTE hashData[32] = { 0 };
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashData, &hashLen, 0)) {
        std::ostringstream oss;
        for (DWORD i = 0; i < hashLen; i++) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hashData[i]);
        }
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

static std::string json_get_string(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.length());
    if (pos == std::string::npos) return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    else if (json[pos] == 'n' && json.substr(pos, 4) == "null") {
        return "";
    }
    else {
        size_t end = json.find_first_of(",}\n\r ", pos);
        if (end == std::string::npos) end = json.size();
        return json.substr(pos, end - pos);
    }
}

static int json_get_int(const std::string& json, const std::string& key, int def = 0)
{
    std::string val = json_get_string(json, key);
    if (val.empty()) return def;
    try { return std::stoi(val); }
    catch (...) { return def; }
}

vt::VTResult vt::lookup_hash(const std::string& api_key, const std::string& sha256)
{
    vt_throttle();

    VTResult result;
    result.sha256 = sha256;

    if (api_key.empty() || sha256.empty()) {
        result.error = true;
        result.error_msg = "missing api_key or hash";
        return result;
    }

    std::string path = "/api/v3/files/" + sha256;
    std::wstring wpath(path.begin(), path.end());

    std::string hdr = "x-apikey: " + api_key;
    std::wstring whdr(hdr.begin(), hdr.end());

    HINTERNET hSession = WinHttpOpen(L"HollowsHunter-VT/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        result.error = true;
        result.error_msg = "WinHttpOpen failed";
        return result;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        result.error = true;
        result.error_msg = "WinHttpConnect failed";
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
        wpath.c_str(), nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        result.error = true;
        result.error_msg = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    WinHttpAddRequestHeaders(hRequest, whdr.c_str(), static_cast<DWORD>(whdr.length()),
        WINHTTP_ADDREQ_FLAG_ADD);

    BOOL bSent = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!bSent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        result.error = true;
        result.error_msg = "HTTP request failed";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

    if (statusCode == 404) {
        result.found = false;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    if (statusCode != 200) {
        result.error = true;
        result.error_msg = "HTTP " + std::to_string(statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::string body;
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize);
        DWORD dwRead = 0;
        WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead);
        body.append(buffer.data(), dwRead);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    result.found = true;

    int malicious = json_get_int(body, "malicious");
    int suspicious_count = json_get_int(body, "suspicious");
    int undetected = json_get_int(body, "undetected");
    int harmless = json_get_int(body, "harmless");
    int type_unsupported = json_get_int(body, "type-unsupported");
    int timeout = json_get_int(body, "timeout");
    int failure = json_get_int(body, "failure");

    result.positives = malicious + suspicious_count;
    result.total = malicious + suspicious_count + undetected + harmless + type_unsupported + timeout + failure;

    result.threat_label = json_get_string(body, "suggested_threat_label");

    result.permalink = "https://www.virustotal.com/gui/file/" + sha256;

    return result;
}

bool vt::write_vt_report(const std::string& output_path, const VTResult& result)
{
    std::ofstream f(output_path);
    if (!f.is_open()) return false;

    f << "{\n";
    f << "  \"sha256\" : \"" << result.sha256 << "\",\n";
    f << "  \"score\" : \"" << result.scoreStr() << "\",\n";
    f << "  \"positives\" : " << result.positives << ",\n";
    f << "  \"total\" : " << result.total << ",\n";
    f << "  \"threat_label\" : \"" << result.threat_label << "\",\n";
    f << "  \"permalink\" : \"" << result.permalink << "\",\n";
    f << "  \"found\" : " << (result.found ? "true" : "false") << ",\n";
    f << "  \"error\" : " << (result.error ? "true" : "false");
    if (result.error) {
        f << ",\n  \"error_msg\" : \"" << result.error_msg << "\"";
    }
    f << "\n}\n";
    f.close();
    return true;
}
