#ifndef MOD_DEFENDER_UTIL_H
#define MOD_DEFENDER_UTIL_H

#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <iostream>
#include <sstream>

using std::vector;
using std::string;
using std::stringstream;
using std::endl;
using std::istringstream;
using std::pair;

class Util {

public:
    static string &ltrim(string &s) { // trim from start
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
    }

    static string &rtrim(string &s) { // trim from end
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
    }

    static string &trim(string &s) { // trim from both ends
        return ltrim(rtrim(s));
    }

    static vector<string> split(string &s, char delim, bool ignoreEscaped = 0);
    static pair<string, string> splitAtFirst(const string &s, char delim);
    static string stringAfter(const string &s, char delim);
    static unsigned int intAfter(const string &s, char delim);
    static string unescape(const string &s);
};


#endif //MOD_DEFENDER_UTIL_H
