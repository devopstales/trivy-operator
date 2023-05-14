import prometheus_client

CONTAINER_VULN_SUM = prometheus_client.Gauge(
    'so_vulnerabilities',
    'Container vulnerabilities',
    ['exported_namespace', 'image', 'severity']
)
CONTAINER_VULN = prometheus_client.Gauge(
    'trivy_vulnerabilities',
    'Container vulnerabilities',
    ['exported_namespace', 'pod', 'image', 'installedVersion',
        'pkgName', 'severity', 'vulnerabilityId']
)
AC_VULN = prometheus_client.Gauge(
    'ac_vulnerabilities',
    'Admission Controller vulnerabilities',
    ['exported_namespace', 'image', 'severity']
)