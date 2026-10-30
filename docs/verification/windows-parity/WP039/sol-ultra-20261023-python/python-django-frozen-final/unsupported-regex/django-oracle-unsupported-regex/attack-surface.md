# Attack Surface

## Priority View
- High-risk entry points: 0
- Public exposure candidates (static inference): 1
- Internal exposure candidates (static inference): 0
- Routes with unknown exposure: 0
- Routes with likely data access: 0
- Routes with outbound trust boundaries: 0

## Highest-Risk Entry Points
- No high-risk entry points were classified

## Auth And Privileged Routes
- No dedicated auth or admin routes were classified

## Public Application Routes
- [LOW] ANY ^items/(?P<pk>[0-9]+)/$ (project/urls.py) -> public_api, public; evidence: static_observed; auth enforcement: unknown; no auth signals observed

## Operational, Internal, And Unknown-Exposure Routes
- No health, metrics, debug, or internal routes were classified

## External Dependencies
- Repository context; route ownership is not established by these signals.
- No explicit outbound HTTP calls detected

## Secrets And Auth Hints
- No secret-like environment variable usage detected
- Auth-related keywords observed: django_auth, login_required, session_middleware
