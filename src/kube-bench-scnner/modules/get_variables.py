import os, kopf
from modules.helper_functions import var_test, get_logger

logger = get_logger(__name__)

IN_CLUSTER = var_test(os.getenv("IN_CLUSTER", False))

try:
    NODE_NAME = os.environ.get("NODE_NAME")
    report_name = ("kube-bench-cis-" + NODE_NAME )
except:
        logger.error("NODE_NAME variable mast configure !!!")
        raise kopf.PermanentError("NODE_NAME variable not set")