# TAKE EXPORTED LOGS FROM SYSLOG WATCHER (readme explains settings) AND IMPORT / FORMAT raw logs VIA PYTHON into MySQL

import sqlalchemy as sa
import pandas as pd
import mySecrets
import datetime as dt
from mailer import sendMail
import time

# JOB TIMER
start = time.perf_counter()
print('FW activity and lookup tables update process STARTED')

logPath = mySecrets.logPath
logFile = "\Jan12-Jan13.csv"

exportPath = "{}{}".format(logPath, logFile)


def processLogs():
    # filename range time is 12:00am
    logs = pd.read_csv(exportPath, sep=",", names=["DOW", "ODATE", "MESSAGE"])
    logs['YEAR'] = logs["MESSAGE"].apply(lambda st: st[0:5])
    logs["DATE"] = logs["ODATE"] + "," + logs["YEAR"]
    logs['DATE'] = pd.to_datetime(logs['DATE'])
    logs["TIME"] = logs["MESSAGE"].apply(lambda st: st[st.find(" ") + 1:st.find("[")])
    logs["TIME"] = logs["TIME"].apply(lambda st: st.split(" ")[1]) + " " + logs["TIME"].apply(lambda st: st.split(" ")[2])
    logs["TIME"] = logs["TIME"].apply(lambda st: dt.datetime.strptime(st, "%I:%M:%S.%f %p"))
    del logs["YEAR"]
    del logs["ODATE"]
    logs["POLICY"] = logs["MESSAGE"].apply(lambda st: st[st.find("[")+1:st.find("]")])
    logs["PROTOCOL"] = logs["MESSAGE"].apply(lambda st: st[st.find("PROTO=") + 6:st.find("SPT")])
    logs["PROTOCOL"] = logs["PROTOCOL"].apply(lambda st: st.split()[0] if "ICMP" in st else st)
    logs["SOURCE"] = logs["MESSAGE"].apply(lambda st: st[st.find('SRC=')+4:st.find("DST")])
    logs["DPT"] = logs["MESSAGE"].apply(lambda st: st[st.find("DPT=")+4:st.find("WINDOW")])
    logs["DPT"] = logs["DPT"].apply(lambda st: st.split()[0])
    logs["DoNotFragment"] = logs["MESSAGE"].apply(lambda st: st.find("DF")).astype(str)
    logs["DoNotFragment"] = logs["DoNotFragment"].apply(lambda st: st.replace('-1', '0')).astype(int).astype(bool)
    logs["HOSTNAME"] = logs["SOURCE"].apply(lambda st: st.split("(")[1] if '(' in st else None)
    logs["HOSTNAME"] = logs["HOSTNAME"].str.replace(")", "")
    logs["SOURCE"] = logs["SOURCE"].apply(lambda st: st.split('(')[0])
    logs["SOURCE"] = logs["SOURCE"].apply(lambda st: st.replace(' ', ''))
    # remove repeated messages, some are as high as 7
    logs = logs[~logs['SOURCE'].str.contains(':')]
    del logs["MESSAGE"]

    return logs


def dbLoad(log):
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        return log.to_sql(name='activity',
                          con=conn,
                          if_exists='append',  # append / replace / fail
                          index=False,
                          dtype={
                                "DATE": sa.types.Date,
                                "TIME": sa.types.TIME(6),
                                "DPT": sa.types.INT
                                }
                          )


# UPDATE LOOKUP table with ipubique IP if not found. Will later be tied to a country name
def lookupUpdate():
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        createLookupSQL = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(14) NOT NULL UNIQUE, COUNTRY CHAR(100))"
        conn.execute(createLookupSQL)

        getUniqueSourcesSQL = '''SELECT DISTINCT(SOURCE) from activity;'''
        UniqueSources = conn.execute(getUniqueSourcesSQL)

        for ip in UniqueSources:
            ip = ip[0]
            insSQL = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(insSQL)


if __name__ == "__main__":
    log = processLogs()
    dbLoad(log)
    lookupUpdate()
    import dbUpdateLookup
    end = time.perf_counter()
    elapsedTime = dt.timedelta(seconds=int(end - start))
    print("***Elapsed Time***  ", elapsedTime)
    sendMail('FW activity and lookup tables update process COMPLETED', "Time Elapsed (secs): {}".format(elapsedTime))
