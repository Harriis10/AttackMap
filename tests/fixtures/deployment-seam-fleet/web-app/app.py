"""C28 config-extraction fixture: the client side.

No CLI flags are needed for this fleet — every seam the calls rely on is
declared by a deployment config in one of the scanned repos (see the
sibling ``auth-api`` / ``feed-generator`` directories):

- ``auth-api:8443`` — listen port declared by ``auth-api/k8s/service.yaml``
  (a k8s Service; the port is *named* https, which must NOT invent a
  protocol — the explicit ``appProtocol: https`` declares it).
- ``feed-generator:9000`` — listen port declared by
  ``feed-generator/docker-compose.yml``; the served scheme (https) is
  declared by ``auth-api/deploy/nginx/edge.conf``'s ``proxy_pass https``.
- ``edge.internal`` / ``feed-edge.internal`` — proxies declared by
  ``auth-api/deploy/nginx/edge.conf`` (nginx upstreams with exactly one
  backend each).
- ``auth.ingress.cluster.local`` — proxy declared by
  ``auth-api/k8s/ingress.yaml`` (an Ingress rule host fronting exactly one
  backend service).

Negative controls in the same fleet: ``auth-api:9999`` (port no declaration
vouches for), ``edge-multiple.internal`` (a proxy whose upstream routes to
two backends — skipped as ambiguous), ``auth-api/k8s/broken-service.yaml``
(malformed YAML — skipped with a note, never guessed), and the plain-http
``get_user_insecure``/``get_feed_insecure`` calls (same host and port as a
resolving call but a scheme contradicting the declared protocol —
scheme_mismatch candidates, never observed links).
"""

import requests


def get_user(uid):
    return requests.get("https://auth-api:8443/users/" + uid)


def get_user_insecure(uid):
    return requests.get("http://auth-api:8443/users/" + uid)


def get_user_undeclared_port(uid):
    return requests.get("https://auth-api:9999/users/" + uid)


def via_edge(uid):
    return requests.get("http://edge.internal/users/" + uid)


def via_ingress(uid):
    return requests.get("https://auth.ingress.cluster.local/users/" + uid)


def via_ambiguous_edge(uid):
    return requests.get("http://edge-multiple.internal/users/" + uid)


def get_feed(fid):
    return requests.get("https://feed-generator:9000/feeds/" + fid)


def get_feed_insecure(fid):
    return requests.get("http://feed-generator:9000/feeds/" + fid)


def via_feed_edge(fid):
    return requests.get("https://feed-edge.internal/feeds/" + fid)
