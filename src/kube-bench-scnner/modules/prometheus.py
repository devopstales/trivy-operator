import prometheus_client

CIS_VULN = prometheus_client.Gauge(
    'cis_results',
    'Details of CIS benchmarks for cluster',
    ['hostname', 'scored', 'status', 'test_number', 'type']
)

def startup_prometheus_client(logger):
    prometheus_client.start_http_server(9115)
    logger.info("Prometheus Exporter started...")