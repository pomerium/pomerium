#!/bin/bash

# requires acme.sh
# see : https://github.com/Neilpang/acme.sh
# uncomment below to install
# curl https://get.acme.sh | sh

# assumes cloudflare, but many DNS providers are supported

export CF_Key="x"
export CF_Email="x@x.com"

$HOME/.acme.sh/acme.sh \
	--issue \
	-d '*.corp.beyondperimeter.com' \
	--dns dns_cf
