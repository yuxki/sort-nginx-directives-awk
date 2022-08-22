#!/bin/sh

awk=$1
expect=`cat tests/sorted-output.txt`
result=`$awk -f sort-nginx-directives.awk tests/input.conf | sort `

if [ "$expect" != "$result" ]; then
  echo "[ERROR]: Unexpected output is found."
  exit 1
fi

expect_include=`cat tests/sorted-output-include.txt`
result_include=`$awk -f sort-nginx-directives.awk -v include_by_find=on tests/input-include.conf | sort `

if [ "$expect_include" != "$result_include" ]; then
  echo "[ERROR]: Unexpected output is found with find_name_opt_include=on option."
  exit 1
fi

expect_err="[ERROR] sort-nginx-directives.awk: sort-nginx-directives@0-9c33b361a14a5021586ff16f1b34bcdc84f1b344d88502a943fc1762fb76c1f6 in the configuration will cause unexpected behavior for this program."
result_err=`$awk -f sort-nginx-directives.awk tests/input-error.conf 2>&1`

if [ "$expect_err" != "$result_err" ]; then
  echo "[ERROR]: Unexpected error has not been emmited. Expected \"$expect_err\" but \"$result_err\""
  exit 1
else
  echo "Pass $awk test."
  exit 0
fi

exit 1
