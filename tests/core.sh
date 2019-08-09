#!/bin/bash

source ./test.sh

declare -a tests=(
    # " -d a=blah" 0
    )

# BODY BODY_NAME URL ARGS ARGS_NAME $HEADERS_VAR:Cookie
declare -a core_rules_tests=(
    # SQL Injections IDs:1000-1099
    "blah"                  0 0 0 0 0 0  0 0 0 0 0
    "select+from"           1 1 1 1 1 1  1 1 1 1 1
    "selected+fromage"      0 0 0 0 0 0  0 0 0 0 0
    "\\\""                  1 1 1 1 1 1  1 1 1 1 1
    "0x0x0x0x"              1 1 1 1 1 1  1 1 1 1 1
    "/*"                    1 1 1 1 1 1  1 1 1 1 1
    "*/"                    1 1 1 1 1 1  1 1 1 1 1
    "|"                     1 1 1 1 1 1  1 1 1 1 1
    "&&"                    1 1 1 1 1 1  0 0 1 0 0
    "----"                  1 1 1 1 1 1  1 1 1 1 1
    ";"                     1 1 1 1 1 0  1 1 1 1 1
    "===="                  1 1 0 1 1 0  1 1 0 1 1
    "("                     1 1 1 1 1 1  1 1 1 1 1
    ")"                     1 1 1 1 1 1  1 1 1 1 1
    "'"                     1 1 1 1 1 1  1 1 1 1 1
    ",,"                    1 1 1 1 1 1  1 1 1 1 1
    "##"                    1 1 1 1 1 1  1 1 0 0 0
    "@@@@"                  1 1 1 1 1 1  1 1 1 1 1

    # OBVIOUS RFI IDs:1100-1199
    "http://"               1 1 0 1 1 1  1 1 0 1 1
    "https://"              1 1 0 1 1 1  1 1 0 1 1
    "ftp://"                1 1 0 1 1 1  1 1 0 1 1
    "sftp://"               1 1 0 1 1 1  1 1 0 1 1
    "zlib://"               1 1 0 1 1 1  1 1 0 1 1
    "data://"               1 1 0 1 1 1  1 1 0 1 1
    "glob://"               1 1 0 1 1 1  1 1 0 1 1
    "phar://"               1 1 0 1 1 1  1 1 0 1 1
    "file://"               1 1 0 1 1 1  1 1 0 1 1
    "gopher://"             1 1 0 1 1 1  1 1 0 1 1

    # Directory traversal IDs:1200-1299
    "...."                  1 1 1 1 1 1  1 1 1 1 1
    "/etc/passwd"           1 1 1 1 1 1  1 1 1 1 1
    "c:\\\\"                1 1 1 1 1 1  1 1 1 1 1
    "cmd.exe"               1 1 1 1 1 1  1 1 1 1 1
    "\\\\"                  1 1 1 1 1 1  1 1 1 1 1

    # Cross Site Scripting IDs:1300-1399
    "<"                     1 1 1 1 1 1  1 1 1 1 1
    ">"                     1 1 1 1 1 1  1 1 1 1 1
    "[["                    1 1 1 1 1 1  1 1 1 1 1
    "]]"                    1 1 1 1 1 1  1 1 1 1 1
    "~~"                    1 1 1 1 1 1  1 1 1 1 1
    "\\\`"                  1 1 1 1 1 1  1 1 1 1 1
    "%20"                   1 1 1 1 1 1  0 0 0 0 0
    "%00<script>alert('abcd');</script>"                   1 1 1 1 1 1  1 1 0 1 1

    # Evading tricks IDs: 1400-1500
    "&#"                    1 1 1 1 1 1  0 0 0 0 0
    "%U"                    1 1 1 1 1 1  1 1 400 1 1
    )


test_count=0
test_passed=0

check_url() {
    # URL = $1
    # OPTIONS = $2
    # Expected action = $3
    req="curl \"$HOST/$1\" $2"
    expected_action="$3"
    status_code=$(echo "$req $curl_ret" | bash)
    # If expected code is not 0 or 1 -> it is an http code
    if ([ $expected_action -ne 0 ] && [ $expected_action -ne 1 ])
    then
        test_msg=$(check_status_code $status_code $expected_action)
    else
        test_msg=$(check_block $status_code $expected_action)
    fi
    test_passed=$((test_passed + $?))
    test_count=$((test_count + 1))
    printf "%-60s %s\n" "$req" "$status_code  $test_msg"
}

for ((i=0; i<${#core_rules_tests[@]}; i+=12)); do
    pattern=${core_rules_tests[$i]}
    # URL encoded
    check_url "" " --data-urlencode \"x=$pattern\"" ${core_rules_tests[$i+1]}
    no_escaped="$(echo "$pattern" | sed 's/\\\(.\{1\}\)/\1/g')"
    check_url "" " --data-raw \"$(url_encode "$no_escaped")=x\"" ${core_rules_tests[$i+2]}
    check_url "$(url_encode "$no_escaped")" "" ${core_rules_tests[$i+3]}
    check_url "?x=$(url_encode "$no_escaped")" "" ${core_rules_tests[$i+4]}
    check_url "?$(url_encode "$no_escaped")=x" "" ${core_rules_tests[$i+5]}
    check_url "" " -b \"x=$pattern\"" ${core_rules_tests[$i+6]}
    # Do NOT URL encode
    check_url "" " --data-raw \"x=$pattern\"" ${core_rules_tests[$i+7]}
    check_url "" " --data-raw \"$pattern=x\"" ${core_rules_tests[$i+8]}
    check_url "$pattern" " -g " ${core_rules_tests[$i+9]}
    check_url "?x=$pattern" " -g " ${core_rules_tests[$i+10]}
    check_url "?$pattern=x" " -g " ${core_rules_tests[$i+11]}
done

# Print results
echo $test_passed/$test_count "tests passed" \($(((test_passed * 100) / test_count))%\)
exit $(($test_passed != $test_count))

