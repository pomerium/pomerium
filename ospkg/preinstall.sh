#!/bin/bash

if ! getent passwd pomerium >/dev/null; then
    useradd --system -d / -s /sbin/nologin pomerium
fi
