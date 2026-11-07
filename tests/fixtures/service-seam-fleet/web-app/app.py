"""C28 service-resolution CLI fixture: the client side.

One call per declaration kind: a proxied destination, a declared listen port
(scheme-consistent), the same port with a contradicting scheme, and a public
host alias. Analyzed together with ``auth-api`` and the flags
``--via-proxy edge.internal=auth-api --service-port auth-api=8443
--service-protocol auth-api=https --service-alias auth.bsky.social=auth-api``.
"""

import requests


def get_user(uid):
    return requests.get("https://edge.internal/users/" + uid)


def get_user_direct(uid):
    return requests.get("https://auth-api:8443/users/" + uid)


def get_user_insecure(uid):
    return requests.get("http://auth-api:8443/users/" + uid)


def get_user_public(oid):
    return requests.get("https://auth.bsky.social/users/" + oid)
