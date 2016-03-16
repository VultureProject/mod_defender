#include "Util.h"

vector<string> Util::split(string &s, char delimiter) {
    vector<string> v;
    size_t pos = 0;
    string token;
    while ((pos = s.find(delimiter)) != string::npos) {
        token = s.substr(0, pos);
        if (token.size() > 0)
            v.push_back(token);
//        s.erase(0, pos + delimiter.length());
        s.erase(0, pos + 1);
    }
    v.push_back(s);

    return v;
}

vector<int> Util::splitToInt(string &s, char delimiter) {
    vector<int> v;
    size_t pos = 0;
    string token;
    while ((pos = s.find(delimiter)) != string::npos) {
        token = s.substr(0, pos);
        if (token.size() > 0)
            v.push_back(std::stoi(token));
        s.erase(0, pos + 1);
    }
    v.push_back(std::stoi(s));

    return v;
}

pair<string, string> Util::splitAtFirst(const string &s, string delim) {
    pair<string, string> p;
    unsigned long delimpos = s.find(delim);
    p.first = s.substr(0, delimpos);
    p.second = s.substr(delimpos + delim.length(), s.size());
    return p;
}

int Util::countSubstring(const std::string &str, const std::string &sub) {
    if (sub.length() == 0) return 0;
    int count = 0;
    for (size_t offset = str.find(sub); offset != std::string::npos;
         offset = str.find(sub, offset + sub.length())) {
        ++count;
    }
    return count;
}