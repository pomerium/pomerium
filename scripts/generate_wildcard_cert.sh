#!/bin/bash

# requires certbot
certbot certonly --manual \
	--agree-tos \
	-d *.corp.example.com \
	--preferred-challenges dns-01 \
	--server https://acme-v02.api.letsencrypt.org/directory \
	--config-dir le/config \
	--logs-dir le/work \
	--work-dir le/work
