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
    static vector<string> split(string &s, char delim);
    static pair<string, string> splitAtFirst(const string &s, char delim);
    static string stringAfter(const string &s, char delim);
    static unsigned int intAfter(const string &s, char delim);
};


#endif //MOD_DEFENDER_UTIL_H
