from __future__ import absolute_import, division, print_function

import argparse
import json
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument('--openid-configuration',
                    default="https://accounts.google.com/.well-known/openid-configuration")
parser.add_argument('--client-id')
parser.add_argument('--client-secret')
parser.add_argument('--pomerium-client-id')
parser.add_argument('--code')
parser.add_argument('--pomerium-token-url',
                    default="https://authenticate.corp.beyondperimeter.com/api/v1/token")
parser.add_argument('--pomerium-token')
parser.add_argument('--pomerium-url', default="https://httpbin.corp.beyondperimeter.com/get")


def main():
    args = parser.parse_args()
    code = args.code
    pomerium_token = args.pomerium_token
    oidc_document = requests.get(args.openid_configuration).json()
    token_url = oidc_document['token_endpoint']
    print(token_url)
    sign_in_url = oidc_document['authorization_endpoint']

    if not code and not pomerium_token:
        if not args.client_id:
            print("client-id is required")
            sys.exit(1)

        sign_in_url = "{}?response_type=code&scope=openid%20email&access_type=offline&redirect_uri=urn:ietf:wg:oauth:2.0:oob&client_id={}".format(
            oidc_document['authorization_endpoint'], args.client_id)
        print("Access code not set, so we'll do the process interactively!")
        print("Go to the url : {}".format(sign_in_url))
        code = input("Complete the login and enter your code:")
        print(code)

    if not pomerium_token:
        req = requests.post(
            token_url, {
                'client_id': args.client_id,
                'client_secret': args.client_secret,
                'code': code,
                'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
                'grant_type': 'authorization_code'
            })

        refresh_token = req.json()['refresh_token']
        print("refresh token: {}".format(refresh_token))

        print("create a new id_token with our pomerium app as the audience")
        req = requests.post(
            token_url, {
                'refresh_token': refresh_token,
                'client_id': args.client_id,
                'client_secret': args.client_secret,
                'audience': args.pomerium_client_id,
                'grant_type': 'refresh_token'
            })
        id_token = req.json()['id_token']
        print("pomerium id_token: {}".format(id_token))

        print("exchange our identity providers id token for a pomerium bearer token")
        req = requests.post(args.pomerium_token_url, {'id_token': id_token})
        pomerium_token = req.json()['Token']
        print("pomerium bearer token is: {}".format(pomerium_token))

    req = requests.get(args.pomerium_url, headers={'Authorization': 'Bearer ' + pomerium_token})
    json_formatted = json.dumps(req.json(), indent=1)
    print(json_formatted)


if __name__ == '__main__':
    main()
