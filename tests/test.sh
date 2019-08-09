#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <host>"
	exit 0
fi
HOST=$1
curl_ret="-s -o /dev/null -w %{http_code}"

PASS_MESSAGE="[ \033[0;32mPASS\033[0m ]"
FAIL_MESSAGE="[ \033[0;31mFAIL\033[0m ]"

check_block() {
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

check_status_code() {
	if ([ $1 == $2 ]) then
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