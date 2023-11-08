import os
from modules.helper_functions import var_test, get_logger

logger = get_logger(__name__)

IN_CLUSTER = var_test(os.getenv("IN_CLUSTER", False))

OFFLINE_ENABLED = var_test(os.getenv("SKIP_DB_UPDATE", False))
DB_REPOSITORY_INSECURE = var_test(os.getenv("DB_REPOSITORY_INSECURE", False))

if OFFLINE_ENABLED:
    DB_REPOSITORY = os.getenv("DB_REPOSITORY")
    if not DB_REPOSITORY:
        TRIVY_OFFLINE = ["--skip-db-update", "--offline-scan"]
    else:
        TRIVY_OFFLINE = ["--db-repository", DB_REPOSITORY]
        if DB_REPOSITORY_INSECURE:
            os.environ['TRIVY_INSECURE'] = "true"
    logger.debug("Trivy offline mode is enabled") # DEBUG-LOG
else:
    DB_REPOSITORY = None
    TRIVY_OFFLINE = None
    logger.debug("Trivy offline mode is disabled") # DEBUG-LOG

REDIS_ENABLED = var_test(os.getenv("REDIS_ENABLED", False))

if REDIS_ENABLED:
    REDIS_BACKEND = os.getenv("REDIS_BACKEND")
    if not REDIS_BACKEND:
        REDIS_ENABLED = False
        logger.warning("Redis Cache Disabled: %s" % (REDIS_BACKEND))
    else:
        TRIVY_REDIS = ["--cache-backend", REDIS_BACKEND]
        logger.warning("Redis Cache Enabled: %s" % (REDIS_BACKEND))
else:
    TRIVY_REDIS = None
    logger.debug("Redis Cache Disabled") # DEBUG-LOG

CURRENT_NAMESPACE = os.environ.get("POD_NAMESPACE", "trivy-operator")

IS_GLOBAL = var_test(os.getenv("IS_GLOBAL", False))
AC_ENABLED = var_test(os.getenv("ADMISSION_CONTROLLER", False))
