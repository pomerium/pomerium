#!/bin/bash
# acme.sh : https://github.com/Neilpang/acme.sh
#			curl https://get.acme.sh | sh
# NOTA BENE:
# if you use a DNS service that supports API access, you may be able to automate
# this process. See https://github.com/Neilpang/acme.sh/wiki/dnsapi

echo "=> first generate a certificate signing request!"
$HOME/.acme.sh/acme.sh \
	--issue \
	-k ec-256 \
	-d '*.corp.example.com' \
	--dns \
	--yes-I-know-dns-manual-mode-enough-go-ahead-please

read -p "press anykey once you've updated your TXT entries"

$HOME/.acme.sh/acme.sh \
	--renew \
	--ecc \
	-k ec-256 \
	-d '*.corp.example.com' \
	--dns \
	--yes-I-know-dns-manual-mode-enough-go-ahead-please
