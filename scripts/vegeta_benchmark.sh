#!/bin/bash
# see: https://github.com/tsenart/vegeta

cookie='cookie: _pomerium_proxy=REPLACE_ME'
url='GET https://hi.corp.beyondperimeter.com/'
rate=100
until [ $rate -gt 10001 ]; do
	echo "${url}" | vegeta attack -header "${cookie}" -name=$rate -rate=$rate -duration=5s >results.$rate.bin
	let rate+=100
	sleep 10
done

for filename in results.*; do
	cat "$filename" | vegeta report
	cat "$filename" | vegeta report -type="hist[0,50ms,100ms,200ms,300ms,500ms,1000ms]"
done
