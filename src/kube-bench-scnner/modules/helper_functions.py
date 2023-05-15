
import logging, six, os, time
from datetime import datetime, timedelta, timezone
from croniter import croniter

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

# Round time down to the top of the previous minute
def roundDownTime(dt=None, dateDelta=timedelta(minutes=1)):
    roundTo = dateDelta.total_seconds()
    if dt == None : dt = datetime.now()
    seconds = (dt - dt.min).seconds
    rounding = (seconds+roundTo/2) // roundTo * roundTo
    return dt + timedelta(0,rounding-seconds,-dt.microsecond)

# Get next run time from now, based on schedule specified by cron string
def getNextCronRunTime(schedule):
    return croniter(schedule, datetime.now()).get_next(datetime)

# Sleep till the top of the next minute
def sleepTillTopOfNextMinute():
    t = datetime.utcnow()
    sleeptime = 60 - (t.second + t.microsecond/1000000.0)
    time.sleep(sleeptime)

def getCurretnTime():
  now = datetime.now().time() # time object
  return now