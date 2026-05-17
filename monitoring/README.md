# Weissman Cybersecurity - Monitoring & Metrics

Prometheus-based monitoring system for production observability.

## Quick Start

### Enable Metrics

```bash
export METRICS_ENABLED=true
export METRICS_PORT=9090
```

### Access Metrics Endpoint

```bash
curl http://localhost:9090/metrics
```

## Available Metrics

### Request Metrics
- `weissman_requests_total{endpoint, method, status}` - Total requests by endpoint
- `weissman_request_duration_seconds{endpoint}` - Request latency histogram

### Rate Limiting
- `weissman_rate_limit_violations_total{identity, key_prefix}` - Rate limit violations by tenant/IP

### Caching
- `weissman_cache_operations_total{cache_key, operation}` - Cache hits/misses by feed

### Scanning
- `weissman_scan_duration_seconds{scan_type}` - Scan execution time histogram
- `weissman_active_scans` - Currently running scans (gauge)

### Errors
- `weissman_errors_total{error_type}` - Errors by exception type

## Grafana Dashboard

Import the provided dashboard from `monitoring/grafana-dashboard.json`:

### Key Panels
1. **Request Rate** - Requests per second by endpoint
2. **Error Rate** - Error percentage over time
3. **Cache Hit Rate** - Feed cache effectiveness
4. **Rate Limit Violations** - Abuse patterns
5. **Scan Performance** - P50/P95/P99 latencies

## Alerting Rules

### Critical Alerts
- High error rate (>5% for 5 minutes)
- Rate limit violations spike (>100/minute)
- Scan duration P99 > 5 minutes

### Warning Alerts
- Cache hit rate < 60%
- Active scans > 50 concurrent

## Integration Examples

### Python Code

```python
from src.metrics import track_request, track_scan_duration

# Track API endpoint
with track_request("api_scan", "POST"):
    # ... scan logic
    pass

# Track scan execution
with track_scan_duration("xss"):
    run_xss_scan(target)
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'weissman'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

### Docker Compose

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Performance Impact

- Metrics collection: < 1ms per operation
- Memory overhead: ~10MB for metric storage
- No impact when METRICS_ENABLED=false

## Troubleshooting

### Metrics Not Appearing

1. Check if metrics are enabled:
```bash
curl http://localhost:9090/metrics | grep weissman
```

2. Verify prometheus_client is installed:
```bash
pip list | grep prometheus
```

3. Check logs:
```bash
grep "metrics:" /var/log/weissman.log
```

### Port Already in Use

Change the metrics port:
```bash
export METRICS_PORT=9091
```

## Security Considerations

- Metrics endpoint should NOT be publicly accessible
- Use firewall rules to restrict access to monitoring systems
- Consider basic auth for production:

```python
# Add authentication middleware
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.security import check_password_hash
```

## Further Reading

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Tutorials](https://grafana.com/tutorials/)
- [Python Client Library](https://github.com/prometheus/client_python)
