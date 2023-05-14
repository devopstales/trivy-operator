from croniter import croniter
from datetime import datetime, timedelta, timezone
import kopf, time

def get_crontab(logger,spec):
    try:
        crontab = spec['crontab']
        logger.debug("namespace-scanners - crontab:") # DEBUG-LOG
        logger.debug(format(crontab)) # DEBUG-LOG
    except:
        logger.error("namespace-scanner: crontab must be set !!!")
        raise kopf.PermanentError("namespace-scanner: crontab must be set")
    return crontab

"""Get next run time from now, based on schedule specified by cron string"""
def getNextCronRunTime(logger,spec):
    schedule = get_crontab(logger,spec)
    return croniter(schedule, datetime.now()).get_next(datetime)

"""Round time down to the top of the previous minute"""
def roundDownTime(dt=None, dateDelta=timedelta(minutes=1)):
    roundTo = dateDelta.total_seconds()
    if dt == None : dt = datetime.now()
    seconds = (dt - dt.min).seconds
    rounding = (seconds+roundTo/2) // roundTo * roundTo
    return dt + timedelta(0,rounding-seconds,-dt.microsecond)

"""Sleep till the top of the next minute"""
def sleepTillTopOfNextMinute():
    t = datetime.utcnow()
    sleeptime = 60 - (t.second + t.microsecond/1000000.0)
    time.sleep(sleeptime)

def getCurretnTime():
  now = datetime.now().time() # time object
  return now