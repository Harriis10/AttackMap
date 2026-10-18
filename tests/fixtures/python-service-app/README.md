# python-service-app (synthetic fixture)

A synthetic multi-framework Python service used by
`tests/test_ecosystem_python.py` as the fixture corpus for the
`ecosystem_python` framework-enrichment overlay (AM052 / C38).

It deliberately packs, in one small tree, the cross-file shapes the
per-file `python-web` pass cannot see:

- a FastAPI app that mounts routers declared in other modules, with
  include-time dependencies and a hardened middleware stack
- a Flask app whose blueprint is registered from another module, with a
  `before_request` auth hook and a custom `login_required` wrapper
  defined in a shared module
- a Django-lite layout: settings (middleware chain, `ROOT_URLCONF`,
  env-driven secrets), a URLconf tree using `include(...)`, decorated
  views, ORM scoping and a raw `.extra(...)` escape
- a Celery worker with a redis broker and async task dispatch
- a pydantic settings module, a SQLAlchemy `text(...)` raw query
  module, and an argparse admin CLI

All hosts are `example.com` / `127.0.0.1`. Nothing here is real code.
