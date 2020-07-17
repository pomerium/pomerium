#!/bin/bash
# A valid client cert
curl -v \
	--cacert out/good-ca.crt \
	--key out/good-curl.key \
	--cert out/good-curl.crt \
	https://127.0.0.1:8443

# an untrusted server ca, but good client cert, reject by client
# curl -v \
# 	--cacert out/bad-ca.crt \
# 	--key out/good-curl.key \
# 	--cert out/good-curl.crt \
# 	https://127.0.0.1:8443

# # an untrusted client cert from unustusted ca (rejected by server)

# curl -v \
# 	--cacert out/good-ca.crt \
# 	--key out/bad-curl.key \
# 	--cert out/bad-curl.crt \
# 	https://127.0.0.1:8443
