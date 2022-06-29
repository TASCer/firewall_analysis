import sqlalchemy as sa
import pandas as pd
import my_secrets
import datetime as dt
import time
import tbl_update_lookup_country
import log_visual_analysis
import historical_visual_analysis

from mailer import send_mail

start = time.perf_counter()
print('Firewall Log Processing and Analysis STARTED')
print('--------------------------------------------')

logPath = my_secrets.logPath
logFile = r"\Jun28-Jun29.csv"

exportPath = f"{logPath}{logFile}"


def process_logs():
    """Takes in a csv log file exported from Syslog Watcher 4.5.2, parses it, and returns a pandas Dataframe"""
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
    logs["HOSTNAME"] = logs["HOSTNAME"].str.replace(")", "", regex=False)
    logs["SOURCE"] = logs["SOURCE"].apply(lambda st: st.split('(')[0])
    logs["SOURCE"] = logs["SOURCE"].apply(lambda st: st.replace(' ', ''))
    logs = logs[~logs['SOURCE'].str.contains(':')]
    del logs["MESSAGE"]

    return logs


# TODO test "SOURCE":sa.types.varchar(15) in order to match lookup table for foreign keys?
def tbl_load_activity(cur_log):
    """Takes in a pandas Dataframe and APPENDs new log records into the MySQL database: activity"""
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))
    with engine.connect() as conn, conn.begin():
        return cur_log.to_sql(name='activity',
                              con=conn,
                              if_exists='append',  # append / replace / fail
                              index=False,
                              dtype={
                                    "DATE": sa.types.Date,
                                    "TIME": sa.types.TIME(6),
                                    "DPT": sa.types.INT
                                    # "SOURCE":sa.types.String(length = 15)
                                    }
                              )


def tbl_load_lookup(ips):
    """Takes distinct ip addresses from processed logs and INSERTS the MySQL database: lookup"""
    engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))
    with engine.connect() as conn, conn.begin():
        create_lookup = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(15), COUNTRY CHAR(100), PRIMARY KEY (SOURCE))"
        conn.execute(create_lookup)

        for ip in ips:
            sql_inserts = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(sql_inserts)


if __name__ == "__main__":
    log = process_logs()
    print(f'Processed {len(log)} log entries')
    unique_sources = log.drop_duplicates(subset='SOURCE')
    unique_sources = unique_sources['SOURCE']
    print(f'{len(unique_sources)} entries were unique')
    tbl_load_activity(log)
    tbl_load_lookup(unique_sources)
    tbl_update_lookup_country.update()
    log_visual_analysis.analyze(log)
    historical_visual_analysis()
    end = time.perf_counter()
    elapsedTime = dt.timedelta(seconds=int(end - start))
    print("***Elapsed Time***  ", elapsedTime)
    send_mail(f"Firewall Analysis COMPLETE: Updated {len(log)} records - {len(unique_sources)} unique.", f"Process Time: {elapsedTime}")
