#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <host>"
	exit 0
fi
HOST=$1

PASS_MESSAGE="[ \033[0;32mPASS\033[0m ]"
FAIL_MESSAGE="[ \033[0;31mFAIL\033[0m ]"

check_status_code() {
	if ([ $2 == 0 ] && ([ $1 == 200 ] || [ $1 == 404 ])) ||
		([ $2 == 1 ] && [ $1 == 403 ]) &&
		[ $1 -lt 500 ]
	then
		printf "$PASS_MESSAGE"
		return 1
	else
		printf "$FAIL_MESSAGE"
		return 0
	fi
}

url_encode() {
	local string="$1"
	local strlen=${#string}
	local encoded=""
	local pos c o

	for ((pos=0; pos<strlen; pos++)); do
		c=${string:$pos:1}
		case "$c" in
			[-_.~a-zA-Z0-9] )
				o="$c";;
			* )
				printf -v o '%%%02x' "'$c"
		esac
		encoded+="$o"
	done
	echo "$encoded"
}

declare -a tests=(
	# " -d a=blah" 0
	)

# BODY BODY_NAME URL ARGS ARGS_NAME $HEADERS_VAR:Cookie
declare -a core_rules_tests=(
	# SQL Injections IDs:1000-1099
	"blah"					0 0 0 0 0 0
	"select+from"			1 1 1 1 1 1
	"\""					1 1 1 1 1 1
	"0x0x0x0x"				1 1 1 1 1 1
	"/*"					1 1 1 1 1 1
	"*/"					1 1 1 1 1 1
	"|"						1 1 1 1 1 1
	"&&"					1 1 1 1 1 1
	"----"					1 1 1 1 1 1
	";"						1 1 1 1 1 0
	"===="					1 1 0 1 1 0
	"("						1 1 1 1 1 1
	")"						1 1 1 1 1 1
	"'"						1 1 1 1 1 1
	",,"					1 1 1 1 1 1
	"##"					1 1 1 1 1 1
	"@@@@"					1 1 1 1 1 1

	# OBVIOUS RFI IDs:1100-1199
	"http://"				1 1 0 1 1 1
	"https://"				1 1 0 1 1 1
	"ftp://"				1 1 0 1 1 1
	"sftp://"				1 1 0 1 1 1
	"zlib://"				1 1 0 1 1 1
	"data://"				1 1 0 1 1 1
	"glob://"				1 1 0 1 1 1
	"phar://"				1 1 0 1 1 1
	"file://"				1 1 0 1 1 1
	"gopher://"				1 1 0 1 1 1

	# Directory traversal IDs:1200-1299
	"...."					1 1 1 1 1 1
	"/etc/passwd"			1 1 1 1 1 1
	"c:\\"					1 1 1 1 1 1
	"cmd.exe"				1 1 1 1 1 1
	"\\"					1 1 1 1 1 1

	# Cross Site Scripting IDs:1300-1399
	"<"						1 1 1 1 1 1
	">"						1 1 1 1 1 1
	"[["					1 1 1 1 1 1
	"]]"					1 1 1 1 1 1
	"~~"					1 1 1 1 1 1
	"\`"					1 1 1 1 1 1
	"%20"					1 1 1 1 1 1

	# Evading tricks IDs: 1400-1500
	"&#"					1 1 1 1 1 1
	"%U"					1 1 1 1 1 1
	)
for ((i=0; i<${#core_rules_tests[@]}; i+=7)); do
	pattern=${core_rules_tests[$i]}
	tests+=(" --data-urlencode x=$pattern" ${core_rules_tests[$i+1]})
	tests+=(" -d $(url_encode "$pattern")=x" ${core_rules_tests[$i+2]})
	tests+=($(url_encode "$pattern") ${core_rules_tests[$i+3]})
	tests+=("?x="$(url_encode "$pattern") ${core_rules_tests[$i+4]})
	tests+=("?$(url_encode "$pattern")=x" ${core_rules_tests[$i+5]})
	tests+=(" -b x=$pattern" ${core_rules_tests[$i+6]})
done

tests_size=${#tests[@]}
test_count=$((tests_size / 2))
test_passed=0

for ((i=0; i<$tests_size; i+=2)); do
	req="curl $HOST/${tests[$i]}"
	expected_action=${tests[$i+1]}
	status_code=`$req -s -o /dev/null -w %{http_code}`
	test_msg=`check_status_code $status_code $expected_action`
	test_passed=$((test_passed + $?))
	printf "%-60s %s\n" "$req" "$status_code  $test_msg"
done

echo $test_passed/$test_count "tests passed" \($(((test_passed * 100) / test_count))%\)
exit $(($test_passed != $test_count))