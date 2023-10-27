import datetime as dt
import logging
import my_secrets
import pandas as pd
import pymysql
import tbl_update_lookup_country
import visual_analysis_historical
import visual_analysis_latest

from datetime import datetime
from logging import Logger, Formatter
from mailer import send_mail
from pandas import Series, DataFrame
from sqlalchemy import create_engine, exc
from sqlalchemy.engine import Engine
from typing import Tuple

now: datetime = dt.datetime.now()
todays_date: str = now.strftime('%D').replace('/', '-')

root_logger: Logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

fh = logging.FileHandler(f'../log_{todays_date}.log')
fh.setLevel(logging.DEBUG)

formatter: Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

root_logger.addHandler(fh)

now: datetime = dt.datetime.now()
todays_date: str = now.strftime('%D').replace('/', '-')

log_path: str = my_secrets.logPath
log_file: str = r"\Oct26-Oct27.csv"

export_path: str = f"{log_path}{log_file}"


def process_logs() -> DataFrame:
    """Takes in a csv log file exported from Syslog Watcher 4.5.2, parses it, and returns a pandas Dataframe"""
    logger.info(f'\t**  Log Processing and Analysis STARTED for period: {log_file[1:].upper().split(".")[0]}\t**')

    try:
        logs: DataFrame = pd.read_csv(export_path, sep=",", names=["DOW", "ODATE", "MESSAGE"])

    except FileNotFoundError as e:
        logger.error(e)
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
    logger.info(f"{len(logs)} logs for the period {log_file[1:].upper()} have been processed")

    return logs


def tbl_load_activity(cur_log: DataFrame) -> None:
    """Takes in a pandas Dataframe and APPENDs new log records into the MySQL database: activity
    :param cur_log: 
    """

    try:
        engine: Engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
                                my_secrets.dbhost, my_secrets.dbname))

    except exc.SQLAlchemyError as e:
        engine = None
        logger.exception(str(e))

    with engine.connect() as conn, conn.begin():

        try:
            create_activity_tbl: str = "CREATE TABLE if not exists activity (id INT auto_increment, DOW varchar(9), DATE date, TIME time(6), POLICY varchar(100), PROTOCOL varchar(20), SOURCE varchar(15), DPT int, DoNotFragment BOOLEAN, HOSTNAME varchar(120), primary key(id));"
            engine.execute(create_activity_tbl)

        except (exc.SQLAlchemyError, exc.DataError, pymysql.err.DataError) as e:
            logger.exception(str(e))

        try:
            cur_log.to_sql(name='activity',
                        con=conn,
                        if_exists='append',
                        index=False,
                           )
        except (exc.SQLAlchemyError, exc.DataError, pymysql.err.DataError) as e:
            logger.exception(str(e))

        logger.info("Activity database has been appended with new logs")


def tbl_load_lookup(unique_ips: list) -> int:
    """Takes distinct ip addresses from processed logs and INSERTS the MySQL database: lookup"""
    engine: Engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))
    with engine.connect() as conn, conn.begin():
        create_lookup: str = "CREATE TABLE IF NOT EXISTS lookup (SOURCE varchar(15), COUNTRY CHAR(100), PRIMARY KEY (SOURCE))"
        conn.execute(create_lookup)

        for ip in unique_ips:
            sql_inserts: str = f"INSERT IGNORE INTO lookup(SOURCE) VALUES('{ip}');"
            conn.execute(sql_inserts)

        new_lookups = conn.execute('''SELECT count(*) FROM fwlogs.lookup where COUNTRY is null;''')
        new_lookups_count: Tuple = tuple(n for n in new_lookups)[0][0]

        return new_lookups_count


if __name__ == "__main__":
    logger: Logger = logging.getLogger(__name__)
    parsed_log: DataFrame = process_logs()
    unique_sources: DataFrame = parsed_log.drop_duplicates(subset='SOURCE')
    unique_sources: Series = unique_sources['SOURCE']
    logger.info(f'{len(unique_sources)} entries had unique source ip')
    tbl_load_activity(parsed_log)
    new_lookup_count: int = tbl_load_lookup(unique_sources)
    logger.info(f"{new_lookup_count} new records added to lookup table")
    tbl_update_lookup_country.update()
    visual_analysis_latest.analyze(parsed_log, log_file)
    # visual_analysis_historical.analyze()
    logger.info(f'\t**  Log Processing and Analysis ENDED for period: {log_file[1:].upper().split(".")[0]}\t  **')
    # send_mail(f"Firewall Analysis COMPLETE: Updated {len(parsed_log)} log entries - {len(unique_sources)} unique. \
    #           {new_lookup_count} lookup table updates", f"view log for details")
