#!/bin/sh

awk=$1
expect=`cat tests/sorted-output.txt`
result=`$awk -f sort-nginx-directives.awk tests/input.conf | sort `

if [ "$expect" != "$result" ]; then
  echo "[ERROR]: Unexpected output is found."
  exit 1
fi

expect_err="[ERROR] sort-nginx-directives.awk: sort-nginx-directives@101ead936a2281d53dcc064b7e2a2ab0d53b92ef3ef7b34b668673007895c860 in the configuration will cause unexpected behavior for this program."
result_err=`$awk -f sort-nginx-directives.awk tests/input-error.conf 2>&1`

if [ "$expect_err" != "$result_err" ]; then
  echo "[ERROR]: Expected error has not been emmited. Expected \"$expect_err\" but \"$result_err\""
  exit 1
else
  exit 0
fi

exit 1
