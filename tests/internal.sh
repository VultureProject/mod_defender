#!/bin/bash

source ./test.sh

test_passed=0
test_count=0

status_code=$(printf %1000000s | tr " " "a" | curl $HOST --data-binary @- $curl_ret)
test_msg=`check_block $status_code 0`
test_passed=$((test_passed + $?))
test_count=$((test_count + 1))
echo -e "sent 1MB                                      " "$req" "$status_code  $test_msg"

status_code=$(printf "%2000000s" | tr " " "a" | curl $HOST --data-binary @- --limit-rate 350k $curl_ret)
test_msg=`check_block $status_code 0`
test_passed=$((test_passed + $?))
test_count=$((test_count + 1))
echo -e "sent 2MB @ 350kb/s                            " "$req" "$status_code  $test_msg"

# Not working on Travis
# status_code=$(printf "%2000000s" | tr " " "a" | curl $HOST --data-binary @- --limit-rate 100k $curl_ret)
# test_msg=`check_status_code $status_code 500`
# test_passed=$((test_passed + $?))
# test_count=$((test_count + 1))
# echo -e "sent 2MB @ 100kb/s (timeout by mod_reqtimeout)" "$req" "$status_code  $test_msg"

status_code=$(printf %10000000s | tr " " "a" | curl $HOST --data-binary @- $curl_ret)
test_msg=`check_block $status_code 1`
test_passed=$((test_passed + $?))
test_count=$((test_count + 1))
echo -e "sent 10MB (too big)                           " "$req" "$status_code  $test_msg"

status_code=$(printf "x=%2000000s+select+from" | tr " " "a" | curl $HOST --data-binary @- $curl_ret)
test_msg=`check_block $status_code 1`
test_passed=$((test_passed + $?))
test_count=$((test_count + 1))
echo -e "x=<200*a>+select+from                         " "$req" "$status_code  $test_msg"

status_code=$(printf "%2000000s+select+from=x" | tr " " "a" | curl $HOST --data-binary @- $curl_ret)
test_msg=`check_block $status_code 1`
test_passed=$((test_passed + $?))
test_count=$((test_count + 1))
echo -e "<200*a>+select+from=x                         " "$req" "$status_code  $test_msg"

echo $test_passed/$test_count "tests passed" \($(((test_passed * 100) / test_count))%\)
exit $(($test_passed != $test_count))