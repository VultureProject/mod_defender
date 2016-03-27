#ifndef MOD_DEFENDER_UTIL_H
#define MOD_DEFENDER_UTIL_H

#include <vector>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

using std::chrono::system_clock;
using namespace std::chrono;
using std::vector;
using std::string;
using std::stringstream;
using std::ostringstream;
using std::endl;
using std::istringstream;
using std::pair;

enum DEF_LOGLEVEL {
    DEFLOG_EMERG = 0,
    DEFLOG_ALERT,
    DEFLOG_CRIT,
    DEFLOG_ERROR,
    DEFLOG_WARN,
    DEFLOG_NOTICE,
    DEFLOG_INFO,
    DEFLOG_DEBUG
};

static const char *logLevels[] = {
        "emerg",
        "alert",
        "crit",
        "error",
        "warn",
        "notice",
        "info",
        "debug",
        NULL
};

namespace Util {
    inline string &ltrim(string &s) { // trim from start
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
    }

    inline string &rtrim(string &s) { // trim from end
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
    }

    inline string &trim(string &s) { // trim from both ends
        return ltrim(rtrim(s));
    }

    inline int countSubstring(const string &str, const string &sub) {
        if (sub.length() == 0) return 0;
        int count = 0;
        for (size_t offset = str.find(sub); offset != std::string::npos;
             offset = str.find(sub, offset + sub.length())) {
            ++count;
        }
        return count;
    }

    inline pair<string, string> kvSplit(const string &s, char delim) {
        pair<string, string> p;
        unsigned long delimpos = s.find(delim);
        if (s.length() > 0 && delimpos >= s.length()) {
            p.first = s;
        }
        else {
            p.first = s.substr(0, delimpos);
            p.second = s.substr(delimpos + 1, s.size());
        }
        return p;
    }

    inline string urlDecode(const string &encoded) {
        CURL *curl = curl_easy_init();
        int outLength;
        char *szRes = curl_easy_unescape(curl, encoded.c_str(), encoded.length(), &outLength);
        string res(szRes, szRes + outLength);
        curl_free(szRes);
        curl_easy_cleanup(curl);
        return res;
    }

    vector<string> split(const string &s, char delim);
    pair<string, string> splitAtFirst(const string &s, string delim);
    vector<int> splitToInt(string &s, char delimiter);
    string apacheTimeFmt();
    string formatLog(enum DEF_LOGLEVEL loglevel, char *client);
}


#endif //MOD_DEFENDER_UTIL_H
