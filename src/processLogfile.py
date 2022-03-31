import sqlalchemy as sa
import pandas as pd
import mySecrets
import datetime as dt
import time
import dbUpdateLookup
import logAnalyzing

from mailer import send_mail

# JOB TIMER
start = time.perf_counter()
print('FW activity and lookup tables update process STARTED')
print('------------------------------------------------------')

logPath = mySecrets.logPath
logFile = r"\Mar30-Mar31.csv"

exportPath = "{}{}".format(logPath, logFile)


def process_logs():
    """Takes in a csv log file, parses it, and returns a pandas Dataframe"""
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
    logs = logs[~logs['SOURCE'].str.contains(':')]
    del logs["MESSAGE"]

    return logs


def db_load(cur_log):
    """Takes in a pandas Dataframe and insert/append into the MySQL database: activity"""
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        return cur_log.to_sql(name='activity',
                              con=conn,
                              if_exists='append',  # append / replace / fail
                              index=False,
                              dtype={
                                    "DATE": sa.types.Date,
                                    "TIME": sa.types.TIME(6),
                                    "DPT": sa.types.INT
                                    }
                              )


def lookup_update():
    """Get distinct source ip addresses and populate the MySQL database: lookup"""
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))
    with engine.connect() as conn, conn.begin():
        create_lookup = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(15) NOT NULL UNIQUE, COUNTRY CHAR(100))"
        conn.execute(create_lookup)

        sql_unique_sources = """SELECT DISTINCT(SOURCE) from activity;"""
        unique_sources = conn.execute(sql_unique_sources)

        for ip in unique_sources:
            ip = ip[0]
            sql_inserts = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(sql_inserts)


if __name__ == "__main__":
    # log = process_logs()
    # processed_count = len(log)
    # print(processed_count)
    # db_load(log)
    # lookup_update()
    dbUpdateLookup.update()
    # end = time.perf_counter()
    # elapsedTime = dt.timedelta(seconds=int(end - start))
    # print("***Elapsed Time***  ", elapsedTime)
    # send_mail(f"activity and lookup tables COMPLETE: Updated {processed_count} records", f"Timer: {elapsedTime} (secs)")
    logAnalyzing.analyze()
