import datetime as dt
import logging
import matplotlib.pyplot as plt
import my_secrets
import pandas as pd


from datetime import datetime
from logging import Logger
from pandas import DataFrame
from sqlalchemy.engine import Engine
from sqlalchemy import create_engine, exc
# from typing import Union, Iterator

now: datetime = dt.datetime.now()
todays_date: str = now.strftime('%D').replace('/', '-')

logger: Logger = logging.getLogger(__name__)


def analyze():
	"""Takes log analysis data stored in databases and presents information to screen and file"""
	try:
		engine: Engine = create_engine(f"mysql+pymysql://{my_secrets.dbuser}:{my_secrets.dbpass}@{my_secrets.dbhost}/{my_secrets.dbname}")

	except exc.SQLAlchemyError as e:
		logger.critical(str(e))
		engine = None
		exit()

	# TODO hostname query takes a long time. groupby.count()?
	with engine.connect() as conn, conn.begin():
		top_countries: DataFrame = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup 
												group by COUNTRY order by hits desc limit 30;''',
							con=conn, index_col='COUNTRY')
		nocountry: DataFrame = pd.read_sql('''SELECT COUNTRY, count(*) as hits from lookup WHERE country = '' 
											or length(country) = 2 or country like '%%HTTP%%' or country = 'unknown' 
											group by country order by hits desc;''',
							con=conn, index_col='COUNTRY')
		freq_ports: DataFrame = pd.read_sql('''SELECT DPT, count(DPT) as hits from activity group by DPT 
											order by hits desc limit 15;''',
							con=conn, index_col='DPT')
		freq_hostnames: DataFrame = pd.read_sql('''SELECT HOSTNAME, count(HOSTNAME) as hits from activity 
												WHERE HOSTNAME != '' group by HOSTNAME order by hits desc limit 15;''',
							con=conn, index_col='HOSTNAME')
		firewall_policies: DataFrame = pd.read_sql('''SELECT POLICY, count(POLICY) as hits from activity 
													where POLICY !='WAN_LOCAL-default-D' group by POLICY;''',
							con=conn, index_col='POLICY')
		hist_start: DataFrame = pd.read_sql('''SELECT DATE from fwlogs.activity order by DATE ASC limit 1;''', con=conn)

		hist_end: DataFrame = pd.read_sql('''SELECT DATE from fwlogs.activity order by DATE desc limit 1;''', con=conn)

	hist_start_date: str = hist_start['DATE'][0]
	hist_end_date: str = hist_end['DATE'][0]

# HISTORICAL - Plot Top 15 SOURCE countrys found accessing firewall
	plt.style.use('ggplot')

	ax = top_countries[:14].plot(kind='bar', color="indigo", fontsize=8)
	ax.set_alpha(.8)
	ax.set_title(f"TOP 15 SOURCE COUNTRIES {hist_start_date} - {hist_end_date})", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	ax.set_ylabel("Hits", fontsize=12)
	ax.set_xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_countries_historical.png', dpi='figure')
	logger.info(f"Top 15 Source Plot Saved ({hist_start_date} - {hist_end_date})")
	plt.pause(30)
	plt.close()

# # HISTORICAL - Plot country ALPHA-2 codes that cannot map to country name
	plt.style.use('ggplot')

	ax = nocountry.plot(kind='bar', color="blue", fontsize=8)
	ax.set_alpha(.2)
	ax.set_title(f"COUNTRY ALPHA-2 NOT RESOLVED - HISTORICAL ({hist_start_date} - {hist_end_date})", fontsize=10)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/no_countries_historical.png')
	logger.info(f"No Country Name Found Historical Plot Saved ({hist_start_date} - {hist_end_date})")
	plt.pause(30)
	plt.close()

# # HISTORICAL - Plot frequent ports used coming into router
	plt.style.use('ggplot')

	ax = freq_ports.plot(kind='bar', color="green", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title(f"TOP 15 Destination Ports ({hist_start_date} - {hist_end_date})", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_ports_historical.png')
	logger.info(f"Top 15 Historical Ports Plot Saved ({hist_start_date} - {hist_end_date})")
	plt.pause(30)
	plt.close()

# # HISTORICAL - Plot frequent hostnames coming into router
	plt.style.use('ggplot')

	ax = freq_hostnames.plot(kind='bar', color="red", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title(f"TOP 15 HOSTNAMES ({hist_start_date} - {hist_end_date})", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_hostnames_historical.png', dpi='figure')
	logger.info(f"Top 15 Historical HOSTNAMES Plot Saved ({hist_start_date} - {hist_end_date})")
	plt.pause(30)
	plt.close()

# # HISTORICAL - Plot firewall Policy usage
	plt.style.use('ggplot')

	try:
		ax = firewall_policies.plot(kind='bar', color="orange", fontsize=10)
		ax.set_alpha(.2)
		ax.set_title(f"Firewall Policies Usage ({hist_start_date} - {hist_end_date})", fontsize=12)

		plt.xticks(rotation=35, ha='right', va='center_baseline')
		plt.tight_layout()

		mng = plt.get_current_fig_manager()
		mng.window.showMaximized()
		plt.show(block=False)
		plt.savefig('../output/fw_policy_usage_historical.png', dpi='figure')
		logger.info(f"Historical Firewall POLICY Use Plot Saved ({hist_start_date} - {hist_end_date})")
		plt.pause(30)
		plt.close()

	except TypeError as e:
		logger.error(str(e) + "for other policies besides DROP")
