# WP032 protocol and alias identity fixture

Three synthetic repositories (`caller`, `api`, `worker`) qualify the core HTTP
contract linker. Kubernetes and nginx files are parsed by the real deployment
alias extractor; the application observations in the focused test are supplied
normalized fixtures, not a claim of application extraction or runtime traffic.

`api` explicitly declares HTTPS. `worker` has a port named `https` but no
`appProtocol`; that name cannot establish TLS. Its HTTP declaration in the full
fixture comes only from the nginx `proxy_pass`. nginx declares single backend
aliases and negative multi-backend cases (different services and one service on
different ports). Namespaced DNS authorities are deliberately undeclared and
must not resolve by shortening a name. The two API paths differ only in case.

The source files are inert source-location anchors for normalized route/call/
taint evidence and snapshot-qualified score references. They are never executed.
