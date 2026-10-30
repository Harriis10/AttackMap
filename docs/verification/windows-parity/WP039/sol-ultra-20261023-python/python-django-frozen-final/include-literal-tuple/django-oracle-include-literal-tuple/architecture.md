# Architecture Summary

## Overview
- AttackMap inferred a web-facing repository with 3 entry points.
- Files scanned: 19
- Languages detected: python
- Inferred entry points: 3
- Datastores detected: none
- External targets detected: none
- Auth hints observed: django_auth, login_required, session_middleware
- Secret-like env references: 0

## Entry Point Concentration
- app/urls.py: 2 routes
- project/urls.py: 1 routes

## Likely Review Starting Point
- Start with `app/urls.py`. It contains 2 of the detected routes and is the fastest place to validate exposure and trust boundaries.

## Analyst Notes
- AttackMap inferred this system shape heuristically from framework patterns, dependencies, and code hints.
- Treat this as an initial map for security review, then validate the highest-risk routes and boundaries manually.
