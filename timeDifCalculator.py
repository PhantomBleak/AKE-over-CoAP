from datetime import datetime,timedelta 

DELTA_T = 30.0
def delta(s1, s2):
    FMT = '%H:%M:%S.%f'
    tdelta = datetime.strptime(s2, FMT) - datetime.strptime(s1, FMT)
    if tdelta.days < 0:
        tdelta = timedelta(
            days=0,
            seconds=tdelta.seconds,
            microseconds=tdelta.microseconds
        )
    return tdelta.total_seconds()

def getCurrrentTime():
    return datetime.now().astimezone().strftime('%H:%M:%S.%f')

def isMessageFresh(s1,s2):
    return float(delta(s1,s2)) < DELTA_T

#print(isMessageFresh("12:00:00.0","12:00:20.20"))