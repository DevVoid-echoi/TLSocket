from prometheus_client import CollectorRegistry, Counter, Gauge, start_http_server

METRICS_REGISTRY = CollectorRegistry()

connection_total = Counter (
    "tlsocket_connections_total", "Total accepted TCP connections",
    registry = METRICS_REGISTRY,
)
connection_active = Gauge (
    "tlsocket_connections_active", "Currently authenticated clients",
    registry = METRICS_REGISTRY,
)
logins_total = Counter (
    "tlsocket_logins_total", "Total login attempts by result",
    ["result"], registry = METRICS_REGISTRY,
)
registration_total = Counter (
    "tlsocket_registrations_total", "Total registration attempts by result",
    ["result"], registry = METRICS_REGISTRY,
)
messages_total = Counter (
    "tlsocket_messages_total", "Total chat messages relayed",
    registry = METRICS_REGISTRY,
)
blocked_ips_active = Gauge (
    "tlsocket_blocked_ips_active", "IPs currently blocked for brute-forcing",
    registry = METRICS_REGISTRY,
)

def start_metrics_server(port: int) -> None: 
    start_http_server(port, registry = METRICS_REGISTRY)