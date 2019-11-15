from __future__ import absolute_import, division, print_function

import argparse
import http.server
import json
import sys
import urllib.parse
import webbrowser
from urllib.parse import urlparse
import requests

done = False

parser = argparse.ArgumentParser()
parser.add_argument("--login", action="store_true")
parser.add_argument(
    "--dst", default="https://httpbin.example.com/headers",
)
parser.add_argument(
    "--refresh-endpoint", default="https://authenticate.example.com/api/v1/refresh",
)
parser.add_argument("--server", default="localhost", type=str)
parser.add_argument("--port", default=8000, type=int)
parser.add_argument(
    "--cred", default="pomerium-cred.json",
)
args = parser.parse_args()


class PomeriumSession:
    def __init__(self, jwt, refresh_token):
        self.jwt = jwt
        self.refresh_token = refresh_token

    def to_json(self):
        return json.dumps(self.__dict__, indent=2)

    @classmethod
    def from_json_file(cls, fn):
        with open(fn) as f:
            data = json.load(f)
            return cls(**data)


class Callback(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # silence http server logs for now
        return

    def do_GET(self):
        global args
        global done
        self.send_response(200)
        self.end_headers()
        response = b"OK"
        if "pomerium" in self.path:
            path = urllib.parse.urlparse(self.path).query
            path_qp = urllib.parse.parse_qs(path)
            session = PomeriumSession(
                path_qp.get("pomerium_jwt")[0],
                path_qp.get("pomerium_refresh_token")[0],
            )
            done = True
            response = session.to_json().encode()
            with open(args.cred, "w", encoding="utf-8") as f:
                f.write(session.to_json())
                print("=> pomerium json credential saved to:\n{}".format(f.name))

        self.wfile.write(response)


def main():
    global args

    dst = urllib.parse.urlparse(args.dst)
    try:
        cred = PomeriumSession.from_json_file(args.cred)
    except:
        print("=> no credential found, let's login")
        args.login = True

    # initial login to make sure we have our credential
    if args.login:
        dst = urllib.parse.urlparse(args.dst)
        query_params = {"redirect_uri": "http://{}:{}".format(args.server, args.port)}
        enc_query_params = urllib.parse.urlencode(query_params)
        dst_login = "{}://{}{}?{}".format(
            dst.scheme, dst.hostname, "/.pomerium/api/v1/login", enc_query_params,
        )
        response = requests.get(dst_login)
        print("=> Your browser has been opened to visit:\n{}".format(response.text))
        webbrowser.open(response.text)

        with http.server.HTTPServer((args.server, args.port), Callback) as httpd:
            while not done:
                httpd.handle_request()

    cred = PomeriumSession.from_json_file(args.cred)
    response = requests.get(
        args.dst,
        headers={
            "Authorization": "Pomerium {}".format(cred.jwt),
            "Content-type": "application/json",
            "Accept": "application/json",
        },
    )
    print(
        "==> request\n{}\n==> response.status_code\n{}\n==>response.text\n{}\n".format(
            args.dst, response.status_code, response.text
        )
    )
    # if response.status_code == 200:
    if response.status_code == 401:
        # user our refresh token to get a new cred
        print("==> got a 401, let's try to refresh that credential")
        response = requests.get(
            args.refresh_endpoint,
            headers={
                "Authorization": "Pomerium {}".format(cred.refresh_token),
                "Content-type": "application/json",
                "Accept": "application/json",
            },
        )
        print(
            "==>request\n{}\n ==> response.status_code\n{}\nresponse.text==>\n{}\n".format(
                args.refresh_endpoint, response.status_code, response.text
            )
        )
        # update our cred!
        with open(args.cred, "w", encoding="utf-8") as f:
            f.write(response.text)
            print("=> pomerium json credential saved to:\n{}".format(f.name))


if __name__ == "__main__":
    main()
