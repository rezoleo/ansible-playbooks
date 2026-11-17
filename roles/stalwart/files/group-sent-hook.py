#!/usr/bin/python3
"""Stalwart MTA hook: copy mail sent as a group into the Sent Items of that group.

Stalwart only saves a sent mail in the Sent folder of its author. This hook is called at the DATA stage of
authenticated SMTP sessions (MtaHook in plan.ndjson.j2). When the sender is a group address, it imports the mail
into the group's Sent Items through JMAP, as an account that is a member of every group (HOOK_USER).
It always answers "accept": a failed copy is logged, never blocks the mail.
"""

import base64
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JMAP = os.environ.get("JMAP_URL", "http://127.0.0.1:8080")
USER = os.environ["HOOK_USER"]
AUTH = (
    "Basic "
    + base64.b64encode(f"{USER}:{os.environ['HOOK_PASSWORD']}".encode()).decode()
)
CAPABILITIES = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]


def request(path, data=None, content_type="application/json"):
    req = urllib.request.Request(
        JMAP + path,
        data=data,
        headers={"Authorization": AUTH, "Content-Type": content_type},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def call(method, args):
    body = json.dumps(
        {"using": CAPABILITIES, "methodCalls": [[method, args, "0"]]}
    ).encode()
    name, result, _ = request("/jmap", body)["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method}: {result}")
    return result


def copy_to_sent(sender, raw):
    # Accounts shared with HOOK_USER, i.e. the groups, by address (refreshed every time: groups change in the plan)
    accounts = {
        a["name"].lower(): i
        for i, a in request("/jmap/session")["accounts"].items()
        if not a["isPersonal"]
    }
    account = accounts.get(sender.lower())
    if account is None:
        return  # Not a group
    sent = call("Mailbox/query", {"accountId": account, "filter": {"role": "sent"}})[
        "ids"
    ]
    if not sent:
        raise RuntimeError(f"{sender} has no Sent Items")
    blob = request(f"/jmap/upload/{account}/", raw, "message/rfc822")["blobId"]
    created = call(
        "Email/import",
        {
            "accountId": account,
            "emails": {
                "copy": {
                    "blobId": blob,
                    "mailboxIds": {sent[0]: True},
                    "keywords": {"$seen": True},
                }
            },
        },
    )
    if "copy" not in created.get("created", {}):
        raise RuntimeError(f"import into {sender}: {created.get('notCreated')}")
    print(
        f"copied a mail sent as {sender} into its Sent Items",
        file=sys.stderr,
        flush=True,
    )


def handle(payload):
    try:
        login = (payload["context"].get("sasl") or {}).get("login")
        sender = payload["envelope"]["from"]["address"]
        if not login or login == USER:
            return
        message = payload["message"]
        raw = (
            "".join(f"{name}:{value}" for name, value in message["headers"])
            + "\r\n"
            + message["contents"]
        )
        copy_to_sent(sender, raw.encode())
    except Exception as error:  # noqa: BLE001 # Never lose the mail because of the copy
        print(f"copy failed: {error!r}", file=sys.stderr, flush=True)


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        reply = b'{"action":"accept"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
        threading.Thread(
            target=handle, args=(payload,)
        ).start()  # After the answer: SMTP does not wait for it

    def log_message(self, format: str, *args) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(
        ("127.0.0.1", int(os.environ.get("HOOK_PORT", "8081"))), Hook
    ).serve_forever()
