/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include "Util.h"

namespace Util {
    vector<string> split(const string &s, char delimiter) {
        vector<string> v;
        size_t last = 0;
        size_t next = 0;
        string token;
        while ((next = s.find(delimiter, last)) != string::npos) {
            token = s.substr(last, next - last);
            if (!token.empty())
                v.push_back(token);
            last = next + 1;
        }
        token = s.substr(last);
        if (!token.empty())
            v.push_back(token);

        return v;
    }

    vector<int> splitToInt(string &s, char delimiter) {
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

    pair<string, string> splitAtFirst(const string &s, string delim) {
        pair<string, string> p;
        unsigned long delimpos = s.find(delim);
        p.first = s.substr(0, delimpos);
        p.second = s.substr(delimpos + delim.length(), s.size());
        return p;
    }

    string apacheTimeFmt() {
        time_t timer;
        char date[20];
        struct tm* tm_info;
        time(&timer);
        tm_info = localtime(&timer);
        strftime(date, 20, "%a %b %d %T", tm_info);

        struct timespec tp;
        clock_gettime(CLOCK_REALTIME, &tp);
        long mic = tp.tv_nsec / 1000;

        std::ostringstream oss;
        oss << date << "." << mic << " ";

        char year[5];
        strftime(year, 5, "%Y", tm_info);
        oss << year;
        return oss.str();
    }

    string naxsiTimeFmt() {
        time_t timer;
        char buffer[26];
        struct tm* tm_info;
        time(&timer);
        tm_info = localtime(&timer);
        strftime(buffer, 26, "%Y/%m/%d %T", tm_info);
        return string(buffer);
    }

    string formatLog(int loglevel, char *client) {
        stringstream ss;
        ss << "[" << apacheTimeFmt() << "] ";
        ss << "[defender:" << logLevels[loglevel] << "] ";
//        ss << "[pid " << getpid() << "] ";
        if (client != NULL)
            ss << "[client " << client << "] ";
        return ss.str();
    }

    int naxsi_unescape_uri(u_char **dst, u_char **src, size_t size, unsigned int type) {
        u_char *d, *s, ch, c, decoded;
        int bad = 0;

        enum {
            sw_usual = 0,
            sw_quoted,
            sw_quoted_second
        } state;

        d = *dst;
        s = *src;

        state = sw_usual;
        decoded = 0;

        while (size--) {
            ch = *s++;
            switch (state) {
                case sw_usual:
                    if (ch == '?'
                        && (type & (UNESCAPE_URI | UNESCAPE_REDIRECT))) {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch == '%') {
                        state = sw_quoted;
                        break;
                    }

                    *d++ = ch;
                    break;
                case sw_quoted:
                    if (ch >= '0' && ch <= '9') {
                        decoded = (u_char) (ch - '0');
                        state = sw_quoted_second;
                        break;
                    }

                    c = (u_char) (ch | 0x20);
                    if (c >= 'a' && c <= 'f') {
                        decoded = (u_char) (c - 'a' + 10);
                        state = sw_quoted_second;
                        break;
                    }

                    /* the invalid quoted character */
                    bad++;
                    state = sw_usual;
                    *d++ = '%';
                    *d++ = ch;
                    break;

                case sw_quoted_second:
                    state = sw_usual;
                    if (ch >= '0' && ch <= '9') {
                        ch = (u_char) ((decoded << 4) + ch - '0');

                        if (type & UNESCAPE_REDIRECT) {
                            if (ch > '%' && ch < 0x7f) {
                                *d++ = ch;
                                break;
                            }

                            *d++ = '%';
                            *d++ = *(s - 2);
                            *d++ = *(s - 1);

                            break;
                        }

                        *d++ = ch;

                        break;
                    }

                    c = (u_char) (ch | 0x20);
                    if (c >= 'a' && c <= 'f') {
                        ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                        if (type & UNESCAPE_URI) {
                            if (ch == '?') {
                                *d++ = ch;
                                goto done;
                            }

                            *d++ = ch;
                            break;
                        }

                        if (type & UNESCAPE_REDIRECT) {
                            if (ch == '?') {
                                *d++ = ch;
                                goto done;
                            }

                            if (ch > '%' && ch < 0x7f) {
                                *d++ = ch;
                                break;
                            }

                            *d++ = '%';
                            *d++ = *(s - 2);
                            *d++ = *(s - 1);
                            break;
                        }

                        *d++ = ch;

                        break;
                    }
                    /* the invalid quoted character */
                    /* as it happened in the 2nd part of quoted character,
                       we need to restore the decoded char as well. */
                    *d++ = '%';
                    *d++ = (u_char) ((0 >= decoded && decoded < 10) ? decoded + '0' : decoded - 10 + 'a');
                    *d++ = ch;
                    bad++;
                    break;
            }
        }

        done:

        *dst = d;
        *src = s;

        return bad;
    }

    string escapeQuotes(const string &before) {
        string after;
        after.reserve(before.length() + 4);
        for (string::size_type i = 0; i < before.length(); ++i) {
            switch (before[i]) {
                case '"':
                case '\\':
                    after += '\\';
                default:
                    after += before[i];
            }
        }
        return after;
    }
}