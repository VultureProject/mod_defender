#ifndef MOD_DEFENDER_UTIL_H
#define MOD_DEFENDER_UTIL_H

#define UNESCAPE_URI       1
#define UNESCAPE_REDIRECT  2

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

typedef struct {
    size_t      len;
    u_char     *data;
} str_t;

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

    inline bool caseEqual(const string &str1, const string &str2) {
        if (str1.size() != str2.size()) {
            return false;
        }
        for (string::const_iterator c1 = str1.begin(), c2 = str2.begin(); c1 != str1.end(); ++c1, ++c2) {
            if (tolower(*c1) != tolower(*c2)) {
                return false;
            }
        }
        return true;
    }

    int naxsi_unescape_uri(u_char **dst, u_char **src, size_t size, unsigned int type);

    /* unescape routine, returns number of nullbytes present */
    inline int naxsi_unescape(str_t *str) {
        u_char *dst, *src;
        u_int nullbytes = 0, bad = 0, i;

        dst = str->data;
        src = str->data;

        bad = (u_int) naxsi_unescape_uri(&src, &dst, str->len, 0);
        str->len = src - str->data;
        //tmp hack fix, avoid %00 & co (null byte) encoding :p
        for (i = 0; i < str->len; i++)
            if (str->data[i] == 0x0) {
                nullbytes++;
                str->data[i] = '0';
            }
        return (nullbytes + bad);
    }

    inline char* strnchr(const char *s, int c, int len) {
        int cpt;
        for (cpt = 0; cpt < len && s[cpt]; cpt++)
            if (s[cpt] == c)
                return ((char *) s + cpt);
        return (NULL);
    }

    vector<string> split(const string &s, char delim);
    pair<string, string> splitAtFirst(const string &s, string delim);
    vector<int> splitToInt(string &s, char delimiter);
    string apacheTimeFmt();
    string formatLog(enum DEF_LOGLEVEL loglevel, char *client);
}


#endif //MOD_DEFENDER_UTIL_H
