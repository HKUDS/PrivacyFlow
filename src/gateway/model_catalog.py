"""Provider model-catalog discovery shared by the admin UI and connectors.

The catalog endpoint is deliberately kept separate from inference routing.  PrivacyFlow
does not translate protocols or rewrite model names at request time; it only
discovers the upstream identifiers and preserves the provider's display metadata
for configuration UIs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

from gateway.model_mapping import build_role_mapping


ModelRequester = Callable[[str], Awaitable[tuple[int, Mapping[str, str], Any]]]

_COMPAT_SUFFIXES = (
    "/api/claudecode",
    "/api/anthropic",
    "/apps/anthropic",
    "/api/coding",
    "/claudecode",
    "/anthropic",
    "/step_plan",
    "/coding",
    "/claude",
)
_INFERENCE_TERMINALS = ("/chat/completions", "/responses", "/messages")
_SAFE_TRACE_HEADERS = {
    "x-request-id",
    "request-id",
    "openai-request-id",
    "x-correlation-id",
    "trace-id",
    "x-trace-id",
}


@dataclass(frozen=True)
class ModelOption:
    """A safe, displayable model entry.

    ``id`` is the only value written into Agent configuration.  ``display_name``
    is advisory UI metadata and never changes the request model identifier.
    """

    id: str
    display_name: str
    owned_by: str = ""
    model_type: str = "model"
    metadata: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "owned_by": self.owned_by or None,
            "type": self.model_type,
        }


@dataclass(frozen=True)
class CatalogError:
    code: str
    category: str
    message: str
    status_code: int | None = None

    def public(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "status_code": self.status_code,
        }


@dataclass
class ModelCatalog:
    """Result of one discovery attempt, including safe diagnostics."""

    models: list[ModelOption] = field(default_factory=list)
    source_endpoint: str = ""
    attempted_endpoints: list[str] = field(default_factory=list)
    status_code: int | None = None
    latency_ms: int = 0
    truncated: bool = False
    fetched_at: int = 0
    error: CatalogError | None = None
    trace_headers: dict[str, str] = field(default_factory=dict)

    @property
    def ids(self) -> list[str]:
        return [item.id for item in self.models]

    def public(self, *, include_attempts: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.error is None,
            "models": self.ids,
            "model_options": [item.public() for item in self.models],
            "model_mapping": build_role_mapping(self.ids),
            "source_endpoint": _safe_public_endpoint(self.source_endpoint) or None,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "truncated": self.truncated,
            "fetched_at": self.fetched_at or None,
            "error": self.error.public() if self.error else None,
            "upstream_trace_headers": dict(self.trace_headers),
        }
        if include_attempts:
            result["attempted_endpoints"] = [
                _safe_public_endpoint(endpoint)
                for endpoint in self.attempted_endpoints
                if _safe_public_endpoint(endpoint)
            ]
        return result


def _is_version_path(path: str) -> bool:
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    return len(segment) > 1 and segment.startswith("v") and segment[1:].isdigit()


def _base_url_without_inference_endpoint(base_url: str) -> str:
    normalized = str(base_url or "").strip().rstrip("/")
    parsed = urlsplit(normalized)
    path = parsed.path.rstrip("/")
    for terminal in _INFERENCE_TERMINALS:
        if path.endswith(terminal):
            path = path[: -len(terminal)].rstrip("/")
            return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    return normalized


def build_model_catalog_urls(
    base_url: str,
    *,
    models_url: str = "",
    strip_local_v1: bool = False,
) -> list[str]:
    """Return ordered, de-duplicated catalog candidates.

    An explicit ``models_url`` wins.  Otherwise the configured Base URL is
    tried first, followed by the known compatibility-prefix siblings used by
    providers such as DeepSeek.  Fallbacks are only attempted for 404/405/501
    responses by :func:`fetch_model_catalog`.
    """

    explicit = str(models_url or "").strip().rstrip("/")
    if explicit:
        if len(explicit) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in explicit):
            return []
        try:
            parsed_explicit = urlsplit(explicit)
            _ = parsed_explicit.port
        except ValueError:
            return []
        if (
            parsed_explicit.scheme not in {"http", "https"}
            or not parsed_explicit.netloc
            or not parsed_explicit.hostname
            or parsed_explicit.username
            or parsed_explicit.password
            or parsed_explicit.query
            or parsed_explicit.fragment
        ):
            return []
        return [explicit]
    try:
        base = _base_url_without_inference_endpoint(base_url)
    except ValueError:
        return []
    if len(base) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in base):
        return []
    parsed = urlsplit(base)
    try:
        _ = parsed.port
    except ValueError:
        return []
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return []
    path = parsed.path.rstrip("/")
    candidates: list[str] = []

    def add(candidate_base: str, suffix: str) -> None:
        candidate = f"{candidate_base.rstrip('/')}{suffix}"
        if candidate not in candidates:
            candidates.append(candidate)

    if _is_version_path(path):
        add(base, "/models")
        if not path.endswith("/v1"):
            add(base, "/v1/models")
    else:
        add(base, "/v1/models")

    has_compat_suffix = False
    for suffix in _COMPAT_SUFFIXES:
        if not path.endswith(suffix):
            continue
        has_compat_suffix = True
        stripped = path[: -len(suffix)].rstrip("/")
        root = urlunsplit((parsed.scheme, parsed.netloc, stripped, "", ""))
        if root and root != base:
            add(root, "/v1/models")
            add(root, "/models")
        break

    if strip_local_v1 and not _is_version_path(path) and not has_compat_suffix:
        add(base, "/models")
    return candidates


def _safe_string(value: Any, *, limit: int = 256) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return ""
    return value


def _safe_public_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except ValueError:
        return ""


def parse_model_catalog(body: Any, *, limit: int | None = 500) -> tuple[list[ModelOption], bool]:
    """Parse common OpenAI/Anthropic/provider list shapes without retaining payloads."""

    candidates: Any = body
    if isinstance(body, dict):
        candidates = body.get("data")
        if not isinstance(candidates, list):
            candidates = body.get("models")
    if not isinstance(candidates, list):
        return [], False

    models: list[ModelOption] = []
    seen: set[str] = set()
    truncated = False
    for item in candidates:
        if isinstance(item, dict):
            model_id = _safe_string(item.get("id") or item.get("model") or item.get("name"))
            display_name = _safe_string(item.get("display_name") or item.get("displayName") or item.get("name")) or model_id
            owned_by = _safe_string(item.get("owned_by") or item.get("ownedBy"), limit=128)
            model_type = _safe_string(item.get("object") or item.get("type"), limit=64) or "model"
        else:
            model_id = _safe_string(item)
            display_name = model_id
            owned_by = ""
            model_type = "model"
        if not model_id or model_id in seen:
            continue
        if limit is not None and len(models) >= limit:
            truncated = True
            break
        seen.add(model_id)
        models.append(ModelOption(model_id, display_name, owned_by, model_type))
    return models, truncated


def classify_catalog_error(status_code: int | None, headers: Mapping[str, str] | None, body: Any = None) -> CatalogError:
    """Map an upstream result to a stable, non-secret UI error category."""

    if status_code is None:
        return CatalogError("PF_UPSTREAM_UNREACHABLE", "unreachable", "The upstream provider could not be reached.")
    if status_code in {401, 403}:
        return CatalogError("PF_UPSTREAM_AUTH", "authentication", "The upstream rejected the catalog credentials.", status_code)
    if status_code == 404:
        return CatalogError("PF_UPSTREAM_MODELS_NOT_FOUND", "not_found", "The provider has no model catalog at the discovered endpoints.", status_code)
    if status_code in {405, 501}:
        return CatalogError("PF_UPSTREAM_MODELS_UNSUPPORTED", "unsupported", "The provider does not support model-list discovery.", status_code)
    content_type = str((headers or {}).get("content-type", "")).lower()
    if 200 <= status_code < 300 and content_type and "json" not in content_type:
        has_catalog_shape = isinstance(body, list) or (
            isinstance(body, dict)
            and (isinstance(body.get("data"), list) or isinstance(body.get("models"), list))
        )
        if not has_catalog_shape:
            return CatalogError("PF_UPSTREAM_NON_JSON", "response_format", "The upstream model-list endpoint returned a non-JSON response.", status_code)
    if 400 <= status_code:
        return CatalogError("PF_UPSTREAM_MODELS_FAILED", "upstream", f"The upstream model-list request returned HTTP {status_code}.", status_code)
    if not isinstance(body, (dict, list)):
        return CatalogError("PF_UPSTREAM_MODEL_CATALOG_INVALID", "response_format", "The model-list response was not a supported JSON shape.", status_code)
    return CatalogError("PF_UPSTREAM_MODEL_CATALOG_EMPTY", "empty", "The upstream returned no usable model identifiers.", status_code)


async def fetch_model_catalog(
    requester: ModelRequester,
    base_url: str,
    *,
    models_url: str = "",
    strip_local_v1: bool = False,
    limit: int | None = 500,
) -> ModelCatalog:
    """Fetch a catalog with cc-switch-compatible URL fallback semantics."""

    started = time.perf_counter()
    candidates = build_model_catalog_urls(base_url, models_url=models_url, strip_local_v1=strip_local_v1)
    result = ModelCatalog(attempted_endpoints=list(candidates))
    if not candidates:
        result.error = CatalogError("PF_MODEL_CATALOG_URL_INVALID", "configuration", "No model-list URL could be derived.")
        return result
    for endpoint in candidates:
        try:
            status, headers, body = await requester(endpoint)
        except Exception as exc:
            result.status_code = None
            timeout = exc.__class__.__name__ in {"TimeoutException", "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout"}
            result.error = CatalogError(
                "PF_UPSTREAM_TIMEOUT" if timeout else "PF_UPSTREAM_UNREACHABLE",
                "timeout" if timeout else "unreachable",
                "The upstream request timed out." if timeout else "The upstream provider could not be reached.",
            )
            result.latency_ms = max(0, round((time.perf_counter() - started) * 1000))
            return result
        result.status_code = int(status)
        result.source_endpoint = endpoint
        result.trace_headers = {
            str(key).lower(): str(value)
            for key, value in (headers or {}).items()
            if str(key).lower() in _SAFE_TRACE_HEADERS
            and str(value)
            and len(str(value)) <= 512
            and all(32 <= ord(char) < 127 for char in str(value))
        }
        if status in {404, 405, 501} and endpoint != candidates[-1]:
            continue
        if not 200 <= status < 300:
            result.error = classify_catalog_error(status, headers, body)
            break
        models, truncated = parse_model_catalog(body, limit=limit)
        result.models = models
        result.truncated = truncated
        if not models:
            result.error = classify_catalog_error(status, headers, body)
        break
    result.fetched_at = int(time.time())
    result.latency_ms = max(0, round((time.perf_counter() - started) * 1000))
    return result


def safe_catalog_cache(value: ModelCatalog) -> dict[str, Any]:
    """Return only non-secret fields suitable for launcher/profile persistence."""

    return {
        "fetched_at": value.fetched_at,
        "source_endpoint": _safe_public_endpoint(value.source_endpoint),
        "models": [item.public() for item in value.models],
        "model_mapping": build_role_mapping(value.ids),
        "truncated": value.truncated,
        "status_code": value.status_code,
        "error": value.error.public() if value.error else None,
    }


def normalize_cached_catalog(value: Any) -> dict[str, Any] | None:
    """Validate old/new cache records without exposing arbitrary JSON."""

    if not isinstance(value, dict):
        return None
    fetched_at = value.get("fetched_at")
    if isinstance(fetched_at, bool) or not isinstance(fetched_at, (int, float)):
        fetched_at = 0
    fetched_at = max(0, min(int(fetched_at), int(time.time()) + 31_536_000))
    source = _safe_public_endpoint(_safe_string(value.get("source_endpoint"), limit=2048))
    raw_models = value.get("models")
    models: list[dict[str, Any]] = []
    if isinstance(raw_models, list):
        options, _ = parse_model_catalog({"data": raw_models}, limit=500)
        models = [item.public() for item in options]
    raw_error = value.get("error")
    error: dict[str, Any] | None = None
    if isinstance(raw_error, dict):
        code = _safe_string(raw_error.get("code"), limit=96)
        category = _safe_string(raw_error.get("category"), limit=64)
        status = raw_error.get("status_code")
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            status = None
        if code or category or status is not None:
            # Cached launcher files are local input and may predate the safe
            # catalog schema. Never replay a persisted free-form error string;
            # the fresh discovery response carries the detailed safe message.
            error = {
                "code": code,
                "category": category,
                "message": "The model catalog could not be loaded.",
                "status_code": status,
            }
    return {
        "fetched_at": fetched_at,
        "source_endpoint": source,
        "models": models,
        "model_mapping": build_role_mapping([item["id"] for item in models]),
        "truncated": bool(value.get("truncated", False)),
        "status_code": (
            int(value["status_code"])
            if isinstance(value.get("status_code"), int)
            and not isinstance(value.get("status_code"), bool)
            and 100 <= value["status_code"] <= 599
            else None
        ),
        "error": error,
    }
