"""C28 config-extraction fixture: the client side.

No CLI flags are needed for this fleet — every seam the calls rely on is
declared by a deployment config in one of the scanned repos (see the
sibling ``auth-api`` / ``feed-generator`` directories):

- ``auth-api:8443`` — listen port declared by ``auth-api/k8s/service.yaml``
  (a k8s Service; the port is *named* https, which must NOT invent a
  protocol declaration).
- ``feed-generator:9000`` — listen port declared by
  ``feed-generator/docker-compose.yml``.
- ``edge.internal`` — proxy declared by ``auth-api/deploy/nginx/edge.conf``
  (an nginx upstream with exactly one backend).

Negative controls in the same fleet: ``auth-api:9999`` (port no declaration
vouches for), ``edge-multiple.internal`` (a proxy whose upstream routes to
two backends — skipped as ambiguous), and ``auth-api/k8s/broken-service.yaml``
(malformed YAML — skipped with a note, never guessed).
"""

import requests


def get_user(uid):
    return requests.get("http://auth-api:8443/users/" + uid)


def get_user_undeclared_port(uid):
    return requests.get("http://auth-api:9999/users/" + uid)


def via_edge(uid):
    return requests.get("http://edge.internal/users/" + uid)


def via_ambiguous_edge(uid):
    return requests.get("http://edge-multiple.internal/users/" + uid)


def get_feed(fid):
    return requests.get("http://feed-generator:9000/feeds/" + fid)
