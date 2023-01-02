import datetime as dt
import historical_visual_analysis
import log_visual_analysis
import logging
import my_secrets
import pandas as pd
import tbl_update_lookup_country
import time

from mailer import send_mail
from sqlalchemy import create_engine, exc, types

now = dt.datetime.now()
todays_date = now.strftime('%D').replace('/', '-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(f'../log_{todays_date}.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

now = dt.datetime.now()
todays_date = now.strftime('%D').replace('/', '-')

start = time.perf_counter()

log_path = my_secrets.logPath
log_file = r"\Jan1-Jan2.csv"

export_path = f"{log_path}{log_file}"

logger.info(f'******Log Processing and Analysis STARTED for period: {log_file}******')


def process_logs():
    """Takes in a csv log file exported from Syslog Watcher 4.5.2, parses it, and returns a pandas Dataframe"""
    try:
        logs = pd.read_csv(export_path, sep=",", names=["DOW", "ODATE", "MESSAGE"])

    except FileNotFoundError as e:
        logger.exception(e)
        logs = None
        exit()

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

    logger.info(f"{len(logs)} logs for the period {log_file} have been processed")
    return logs


def tbl_load_activity(cur_log: pd.DataFrame) -> pd.DataFrame:
    """Takes in a pandas Dataframe and APPENDs new log records into the MySQL database: activity"""
    try:
        engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
                                my_secrets.dbhost, my_secrets.dbname))

    except exc.SQLAlchemyError as e:
        engine = None
        logger.exception(str(e))

    with engine.connect() as conn, conn.begin():
        try:
            cur_log.to_sql(name='activity',
                        con=conn,
                        if_exists='append',
                        index=False,
                        dtype={
                            "DATE": types.Date,
                            "TIME": types.TIME(6),
                            "DPT": types.INT,
                            'DoNotFragment': types.BOOLEAN,
                            'DOW': types.VARCHAR(8)
                              }
                           )
        except exc.SQLAlchemyError as e:
            logger.exception(str(e))

        try:
            conn.execute('CREATE INDEX idx_dpt ON activity(DPT);')
            conn.execute('CREATE INDEX idx_date ON activity(DATE);')
            conn.execute('CREATE INDEX idx_dow ON activity(DOW);')

        except exc.SQLAlchemyError as e:
            logger.exception(str(e))

        logger.info("Activity database has been appended with new logs")


def tbl_load_lookup(unique_ips: list) -> int:
    """Takes distinct ip addresses from processed logs and INSERTS the MySQL database: lookup"""
    engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))
    with engine.connect() as conn, conn.begin():
        create_lookup = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(15), COUNTRY CHAR(100), PRIMARY KEY (SOURCE))"
        conn.execute(create_lookup)

        for ip in unique_ips:
            sql_inserts = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(sql_inserts)

        new_lookups = conn.execute('''SELECT count(*) FROM fwlogs.lookup where COUNTRY is null;''')
        new_lookups_count = tuple(n for n in new_lookups)[0][0]

        return new_lookups_count


if __name__ == "__main__":
    parsed_log = process_logs()
    unique_sources = parsed_log.drop_duplicates(subset='SOURCE')
    unique_sources = unique_sources['SOURCE']
    logger.info(f'{len(unique_sources)} entries had unique source ip')
    tbl_load_activity(parsed_log)
    new_lookup_count = tbl_load_lookup(unique_sources)
    logger.info(f"{new_lookup_count} new records added to lookup table")
    tbl_update_lookup_country.update()
    log_visual_analysis.analyze(parsed_log, log_file)
    historical_visual_analysis.analyze()
    end = time.perf_counter()
    elapsedTime = dt.timedelta(seconds=int(end - start))
    logger.info(f'------Log Processing and Analysis ENDED for period: {log_file}------')
    send_mail(f"Firewall Analysis COMPLETE: Updated {len(parsed_log)} log entries - {len(unique_sources)} unique. \
              {new_lookup_count} lookup table updates", f"Process Time: {elapsedTime}")
