#include "Util.h"

vector<string> Util::split(const string &s, char delimiter) {
    vector<string> v;
    size_t last = 0;
    size_t next = 0;
    string token;
    while ((next = s.find(delimiter, last)) != string::npos) {
        token = s.substr(last, next-last);
        if (!token.empty())
            v.push_back(token);
        last = next + 1;
    }
    token = s.substr(last);
    if (!token.empty())
        v.push_back(token);

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

pair<string, string> Util::kvSplit(const string &s, char delim) {
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

string Util::apacheTimeFmt() {
    stringstream ss;
    high_resolution_clock::time_point p = high_resolution_clock::now();

    milliseconds millis = duration_cast<milliseconds>(p.time_since_epoch());
    microseconds micros = std::chrono::duration_cast<std::chrono::microseconds>(p.time_since_epoch());

    seconds s = duration_cast<seconds>(millis);
    std::time_t t = s.count();
    int fractional_seconds = millis.count() % 1000;
    int fractional_millis = micros.count() % 1000;

    std::tm * ptm = std::localtime(&t);
    ss << std::put_time(ptm, "%a %b %d %T");
    ss << ".";
    ss << std::setfill('0') << std::setw(3) << fractional_seconds;
    ss << std::setfill('0') << std::setw(3) << fractional_millis;
    ss << " ";
    ss << std::put_time(ptm, "%Y");
    return ss.str();
}

string Util::formatLog(enum DEF_LOGLEVEL loglevel, char* client) {
    stringstream ss;
    ss << "[" << Util::apacheTimeFmt() << "] ";
    ss << "[defender:" << logLevels[loglevel] << "] ";
    ss << "[pid " << getpid() << "] ";
    if (client != NULL)
        ss << "[client " << client << "] ";
    return ss.str();
}