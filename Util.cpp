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

pair<string, string> Util::splitAtFirst(const string &s, string delim) {
    pair<string, string> p;
    unsigned long delimpos = s.find(delim);
    p.first = s.substr(0, delimpos);
    p.second = s.substr(delimpos + delim.length(), s.size());
    return p;
}

string Util::stringAfter(const string &s, char delim) {
    unsigned long delimpos = s.find(delim);
    string r = s.substr(delimpos + 1, s.size());
    return r;
}

int Util::intAfter(const string &s, char delim) {
    unsigned long delimpos = s.find(delim);
    string r = s.substr(delimpos + 1, s.size());
    return std::stoi(r);
}