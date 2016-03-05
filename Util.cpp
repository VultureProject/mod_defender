#include "Util.h"

vector<string> Util::split(string &s, char delimiter, bool ignoreEscaped) {
    vector<string> v;
    size_t pos = 0;
    string token;
    while ((pos = s.find(delimiter)) != string::npos) {
        if (ignoreEscaped && pos > 1 && s[pos-1] == '\\' && s[pos-2] != '\\') { // soit 2 soit aucun \ devant
            pos = s.find(delimiter, pos+1);
            if (pos == string::npos)
                break;
        }
        token = s.substr(0, pos);
        token = trim(token);
        if (ignoreEscaped)
            token = Util::unescape(token);
        if (token.size() > 0)
            v.push_back(token);
//        s.erase(0, pos + delimiter.length());
        s.erase(0, pos + 1);
    }
    v.push_back(s);

    return v;
}

pair<string, string> Util::splitAtFirst(const string &s, char delim) {
    pair<string, string> p;
    unsigned long delimpos = s.find(delim);
    p.first = s.substr(0, delimpos);
    p.second = s.substr(delimpos + 1, s.size());
    return p;
}

string Util::stringAfter(const string &s, char delim) {
    unsigned long delimpos = s.find(delim);
    string r = s.substr(delimpos + 1, s.size());
    return r;
}

unsigned int Util::intAfter(const string &s, char delim) {
    unsigned long delimpos = s.find(delim);
    string r = s.substr(delimpos + 1, s.size());
    return std::stoi(r);
}

string Util::unescape(const string &s) {
    string res;
    string::const_iterator it = s.begin();
    while (it != s.end()) {
        char c = *it++;
        if (c == '\\' && it != s.end()) {
            switch (*it++) {
                case '\\':
                    c = '\\';
                    break;
                case 'n':
                    c = '\n';
                    break;
                case 't':
                    c = '\t';
                    break;
                case '"':
                    c = '\"';
                    break;
                case 'r':
                    c = '\r';
                    break;
                default:
                    continue;
            }
        }
        res += c;
    }

    return res;
}