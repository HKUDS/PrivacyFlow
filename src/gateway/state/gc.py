from __future__ import annotations

from gateway.mapping_store import MappingStore


def run_gc(store: MappingStore) -> int:
    return store.expire_request_scope()
