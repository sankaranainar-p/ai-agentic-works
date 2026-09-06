"""pre/api — Thin FastAPI route layer.

All business logic lives in pre.agent_loop, pre.database, pre.agent_log,
etc. Route handlers here only: validate input, call into those modules,
and shape the HTTP response.
"""
