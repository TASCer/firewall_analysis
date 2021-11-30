# WORKING ON ABLE TO EXPORT FROM SYSLOG WATCHER AND IMPORT / FORMAT raw logs VIA PYTHON not PowerBI FOR 2022

import sqlalchemy as sa
import pandas as pd
import datetime as dt
import mySecrets

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)


def processLogs():
    logs = pd.read_csv(r"\\NAS\tascs\PowerBIModels\SyslogFiles\2021\.csv", sep=",", names=["DOW", "ODATE", "MESSAGE"])  # Nov25-28
    logs['YEAR'] = logs["MESSAGE"].apply(lambda st: st[0:5])
    logs["DATE"] = logs["ODATE"] + "," + logs["YEAR"]
    logs['DATE'] = pd.to_datetime(logs['DATE'])  # yyyy/mm/dd
    logs["TIME"] = logs["MESSAGE"].apply(lambda st: st[st.find(" ") + 1:st.find("[")])
    logs["TIME"] = logs["TIME"].apply(lambda st: st.split(" ")[1]) + " " + logs["TIME"].apply(lambda st: st.split(" ")[2])
    logs["TIME"] = logs["TIME"].apply(lambda st: dt.datetime.strptime(st, "%I:%M:%S.%f %p")) # dt obj= "1900-01-01 12:05:48.154"
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
    logs = logs[~logs['SOURCE'].str.contains(':')] # removes repeated messages, some are as high as 7

    del logs["MESSAGE"]

    return logs


def dbLoad(log):
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        return  log.to_sql(name='activity',
                  con=conn,
                  if_exists='append',  # append / replace / fail
                  index=False,
                  dtype={
                        "DATE": sa.types.Date,
                        "TIME": sa.types.TIME(6),
                        "DPT": sa.types.INT
                        }
                  )


# UPDATE LOOKUP db with ip if not found, will later be xlated to a country name
def lookupUpdate():
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        createLookupSQL = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(14) NOT NULL UNIQUE, COUNTRY CHAR(100))"
        conn.execute(createLookupSQL)

        getUniqueSourcesSQL = '''SELECT DISTINCT(SOURCE) from activity;'''
        UniqueSources = conn.execute(getUniqueSourcesSQL)
        # print(UniqueSources, type(UniqueSources))

        for ip in UniqueSources:
            ip = ip[0]
            # print(ip)
            insSQL = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(insSQL)


if __name__ == "__main__":
    log = processLogs()
    dbLoad(log)
    lookupUpdate()
    import dbUpdateLookup

