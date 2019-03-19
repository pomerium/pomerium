#!/bin/bash
# requires acme.sh see : https://github.com/Neilpang/acme.sh
# curl https://get.acme.sh | sh
echo "=> manually issue a wildcard certificate, renewal is up to you!"
$HOME/.acme.sh/acme.sh \
	--issue \
	-k ec-256 \
	-d '*.corp.beyondperimeter.com' \
	--dns \
	--yes-I-know-dns-manual-mode-enough-go-ahead-please
