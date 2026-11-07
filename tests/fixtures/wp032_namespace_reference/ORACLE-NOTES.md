# Source-backed service-resolution oracle

This fixture is static input. Its JavaScript calls and Flask routes are scanned;
they are never executed. No normalized observations are supplied by the verifier.

The two `auth-api` repositories intentionally have identical Python sources and
different explicit deployment namespaces. Only the declared ingress hosts bind a
namespace to the exact source root. No `.svc.cluster.local` alias is inferred.

`expected.json` records source lines and exact link classifications. The initial
reference classifications preceded runtime qualification. The multi-backend
`multi.example` candidate reason was corrected from `ambiguous_identity` to
`unresolved_host` after inspecting the existing negative-fact contract: nginx
retains a host-wide unresolved topology flag, not owner identities. The external
host has no matching repository identity. Both links remain candidates; no
positive expectation was relaxed. Core author independently confirmed this.

The `grpc` and conflicting HTTP/HTTPS Service variants retain the exact scoped
topology while their named negative protocol fact requires `unsupported_protocol`
on the owning repository. They cannot fall back to an observed HTTP edge.

The `port-mismatch` variant declares Service backend 8080 and Ingress backend
9999. That invalid association cannot qualify the external ingress hostname:
both matching servers remain `candidate:unresolved_host`, with no attributed
backend namespace/port/protocol/declaration references. The valid dev ingress
remains the positive control. A Service backend port never establishes the
frontend ingress listener port. This expectation was pinned from the explicit
Service/Ingress contract before the corrected runtime qualification.

These synthetic sources qualify explicit static facts and source associations.
They do not establish runtime traffic, TLS/mTLS, detector maturity, rendering,
production-fleet coverage or release acceptance.
