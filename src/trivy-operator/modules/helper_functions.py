
import logging, six, os

##############################################################
## Helper Functions
##############################################################

def get_logger(name):
    logger = logging.getLogger(name)
    level = os.getenv('LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(
            level=level,
            format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
        )
    return logger

def get_logger_level(logger):
    logger_level = logger.getEffectiveLevel()
    return logger_level

def var_test(var):
    if isinstance(var, bool):
        resp = var
    elif isinstance(var, six.string_types):
        if var.lower() in ['true']:
            resp = True
        else:
            resp = False
    else:
        resp = False
    return resp