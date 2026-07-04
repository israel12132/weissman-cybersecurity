"""
src/metrics.py
==============
Prometheus metrics integration for monitoring and observability.

Provides metrics for:
- Request counts and latency
- Rate limit violations
- Feed cache hit/miss rates
- Scan execution times
- Error rates by type

Usage:
    from src.metrics import (
        track_request,
        track_rate_limit_exceeded,
        track_cache_hit,
        track_scan_duration,
    )

    with track_request("api_scan"):
        # ... scan logic
        pass

    track_rate_limit_exceeded("tenant123", "scan_trigger")
    track_cache_hit("nvd", hit=True)
"""

import functools
import logging
import os
import time
from contextlib import contextmanager
from typing import Optional, Any

logger = logging.getLogger("weissman.metrics")

# Metrics enabled via environment variable
METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "false").lower() in ("true", "1", "yes")
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9090"))

# Lazy-init prometheus client
_prometheus_client: Optional[Any] = None
_metrics_initialized = False


def _init_prometheus():
    """Lazy initialization of Prometheus client."""
    global _prometheus_client, _metrics_initialized

    if _metrics_initialized:
        return _prometheus_client

    if not METRICS_ENABLED:
        logger.debug("metrics: disabled (set METRICS_ENABLED=true to enable)")
        _metrics_initialized = True
        return None

    try:
        from prometheus_client import Counter, Histogram, Gauge, start_http_server

        _prometheus_client = {
            "Counter": Counter,
            "Histogram": Histogram,
            "Gauge": Gauge,
        }

        # Start metrics HTTP server
        start_http_server(METRICS_PORT)
        logger.info("metrics: Prometheus endpoint started on port %d", METRICS_PORT)

        _metrics_initialized = True
        return _prometheus_client

    except ImportError:
        logger.warning("metrics: prometheus_client not installed, metrics disabled")
        _metrics_initialized = True
        return None
    except Exception as exc:
        logger.warning("metrics: failed to initialize Prometheus (%s)", exc)
        _metrics_initialized = True
        return None


# Metric definitions (lazy-loaded)
_request_count: Optional[Any] = None
_request_duration: Optional[Any] = None
_rate_limit_violations: Optional[Any] = None
_cache_operations: Optional[Any] = None
_scan_duration: Optional[Any] = None
_error_count: Optional[Any] = None
_active_scans: Optional[Any] = None


def _get_metrics():
    """Get or create metric instances."""
    global _request_count, _request_duration, _rate_limit_violations
    global _cache_operations, _scan_duration, _error_count, _active_scans

    prom = _init_prometheus()
    if not prom:
        return None

    if _request_count is None:
        _request_count = prom["Counter"](
            "weissman_requests_total",
            "Total number of requests",
            ["endpoint", "method", "status"],
        )

    if _request_duration is None:
        _request_duration = prom["Histogram"](
            "weissman_request_duration_seconds",
            "Request duration in seconds",
            ["endpoint"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
        )

    if _rate_limit_violations is None:
        _rate_limit_violations = prom["Counter"](
            "weissman_rate_limit_violations_total",
            "Total rate limit violations",
            ["identity", "key_prefix"],
        )

    if _cache_operations is None:
        _cache_operations = prom["Counter"](
            "weissman_cache_operations_total",
            "Cache operations (hit/miss)",
            ["cache_key", "operation"],
        )

    if _scan_duration is None:
        _scan_duration = prom["Histogram"](
            "weissman_scan_duration_seconds",
            "Scan execution time",
            ["scan_type"],
            buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
        )

    if _error_count is None:
        _error_count = prom["Counter"](
            "weissman_errors_total",
            "Total errors by type",
            ["error_type"],
        )

    if _active_scans is None:
        _active_scans = prom["Gauge"](
            "weissman_active_scans",
            "Number of currently active scans",
        )

    return {
        "request_count": _request_count,
        "request_duration": _request_duration,
        "rate_limit_violations": _rate_limit_violations,
        "cache_operations": _cache_operations,
        "scan_duration": _scan_duration,
        "error_count": _error_count,
        "active_scans": _active_scans,
    }


@contextmanager
def track_request(endpoint: str, method: str = "GET"):
    """
    Context manager to track request metrics.

    Parameters
    ----------
    endpoint : str
        API endpoint name (e.g., "api_scan", "api_export")
    method : str
        HTTP method (GET, POST, etc.)

    Example
    -------
    with track_request("api_scan", "POST"):
        # ... scan logic
        pass
    """
    metrics = _get_metrics()
    start_time = time.time()
    status = "200"

    try:
        yield
    except Exception as exc:
        status = "500"
        if metrics:
            metrics["error_count"].labels(error_type=type(exc).__name__).inc()
        raise
    finally:
        duration = time.time() - start_time
        if metrics:
            metrics["request_count"].labels(
                endpoint=endpoint,
                method=method,
                status=status,
            ).inc()
            metrics["request_duration"].labels(endpoint=endpoint).observe(duration)


def track_rate_limit_exceeded(identity: str, key_prefix: str):
    """
    Track rate limit violation.

    Parameters
    ----------
    identity : str
        Tenant ID or IP that exceeded limit
    key_prefix : str
        Rate limiter key prefix (e.g., "scan_trigger")
    """
    metrics = _get_metrics()
    if metrics:
        metrics["rate_limit_violations"].labels(
            identity=identity,
            key_prefix=key_prefix,
        ).inc()


def track_cache_hit(cache_key: str, hit: bool):
    """
    Track cache hit or miss.

    Parameters
    ----------
    cache_key : str
        Cache key (e.g., "nvd:global")
    hit : bool
        True for cache hit, False for cache miss
    """
    metrics = _get_metrics()
    if metrics:
        operation = "hit" if hit else "miss"
        metrics["cache_operations"].labels(
            cache_key=cache_key,
            operation=operation,
        ).inc()


@contextmanager
def track_scan_duration(scan_type: str):
    """
    Context manager to track scan duration.

    Parameters
    ----------
    scan_type : str
        Type of scan (e.g., "xss", "sqli", "full_scan")

    Example
    -------
    with track_scan_duration("xss"):
        # ... scan logic
        pass
    """
    metrics = _get_metrics()
    start_time = time.time()

    if metrics:
        metrics["active_scans"].inc()

    try:
        yield
    finally:
        duration = time.time() - start_time
        if metrics:
            metrics["scan_duration"].labels(scan_type=scan_type).observe(duration)
            metrics["active_scans"].dec()


def track_error(error_type: str):
    """
    Track error occurrence.

    Parameters
    ----------
    error_type : str
        Type of error (exception class name)
    """
    metrics = _get_metrics()
    if metrics:
        metrics["error_count"].labels(error_type=error_type).inc()


def metrics_middleware(func):
    """
    Decorator to add metrics tracking to a function.

    Example
    -------
    @metrics_middleware
    async def my_endpoint():
        # ... endpoint logic
        pass
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        endpoint_name = func.__name__
        with track_request(endpoint_name):
            return await func(*args, **kwargs)

    return wrapper


# Health check endpoint for metrics
def get_metrics_health() -> dict:
    """
    Get metrics system health status.

    Returns
    -------
    dict
        {
            "enabled": bool,
            "prometheus_initialized": bool,
            "port": int,
        }
    """
    return {
        "enabled": METRICS_ENABLED,
        "prometheus_initialized": _metrics_initialized and _prometheus_client is not None,
        "port": METRICS_PORT if METRICS_ENABLED else None,
    }
