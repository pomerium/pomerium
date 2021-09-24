#!/bin/bash
scriptname="$(basename $0)"

if [ $# -lt 3 ]
 then
    echo "Usage: $scriptname start | stop  POMERIUM_ROUTE LOCAL_PORT"
    exit
fi

case "$1" in

start)
  echo "Starting Pomerium Tunnel to $2"
  pomerium-cli tcp $2 --listen $3 &
  ;;
stop)
  echo "Stopping Pomerium tunnel to $3"
  kill $(pgrep -f "pomerium-cli tcp $2 --listen $3")
 ;;
*)
  echo "Did not understand your argument, please use start|stop"
  ;;

esac
