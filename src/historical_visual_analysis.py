import matplotlib.pyplot as plt
import my_secrets
import logging
import pandas as pd

from sqlalchemy import create_engine, exc

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('../log.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)


# TODO ADD logging and try/except
def analyze():
	"""Takes log analysis data stored in databases and presents information to screen and file"""
	try:
		engine = create_engine(
			"mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost,
											my_secrets.dbname))
	except exc.SQLAlchemyError as e:
		logger.critical(str(e))
		engine = None
		exit()

	with engine.connect() as conn, conn.begin():
		top_countries = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup group by COUNTRY order by hits desc limit 30;''',
							con=conn, index_col='COUNTRY')
		nocountry = pd.read_sql('''SELECT COUNTRY, count(*) as hits from lookup WHERE country is null or country = ''
							or length(country) = 2 group by country order by hits desc;''',
							con=conn, index_col='COUNTRY')
		freq_ports = pd.read_sql('''SELECT DPT, count(DPT) as hits from activity group by DPT order by hits desc limit 15;''',
							con=conn, index_col='DPT')
		freq_hostnames = pd.read_sql('''SELECT HOSTNAME, count(HOSTNAME) as hits from activity WHERE HOSTNAME != '' group by HOSTNAME order by hits desc limit 15;''',
							con=conn, index_col='HOSTNAME')
		firewall_policies = pd.read_sql('''SELECT POLICY, count(POLICY) as hits from activity where POLICY !='WAN_LOCAL-default-D' group by POLICY;''',
							con=conn, index_col='POLICY')

# HISTORICAL - Plot Top 15 SOURCE countrys found accessing firewall
	plt.style.use('ggplot')

	ax = top_countries[:14].plot(kind='bar', color="indigo", fontsize=8)
	# print(ax)
	ax.set_alpha(.8)
	ax.set_title("TOP 15 SOURCE COUNTRIES - HISTORICAL", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	ax.set_ylabel("Hits", fontsize=12)
	ax.set_xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_countries_historical.png', dpi='figure')
	logger.info(f"Top 15 Historical Source Plot Saved")
	plt.pause(30)
	plt.close()

# HISTORICAL - Plot country ALPHA-2 codes that cannot map to country name
	plt.style.use('ggplot')

	ax = nocountry.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("COUNTRY ALPHA-2 NOT RESOLVED - HISTORICAL", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/no_countries_historical.png')
	logger.info(f"No Country Name Historical Plot Saved")
	plt.pause(30)
	plt.close()

# HISTORICAL - Plot frequent ports used coming into router
	plt.style.use('ggplot')

	ax = freq_ports.plot(kind='bar', color="green", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 Destination Ports - HISTORICAL", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_ports_historical.png')
	logger.info(f"Top 15 Historical Ports Plot Saved")
	plt.pause(30)
	plt.close()

# HISTORICAL - Plot frequent hostnames coming into router
	plt.style.use('ggplot')

	ax = freq_hostnames.plot(kind='bar', color="red", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 HOSTNAMES - HISTORICAL", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_hostnames_historical.png', dpi='figure')
	logger.info(f"Top 15 Historical HOSTNAMES Plot Saved")
	plt.pause(30)
	plt.close()

# HISTORICAL - Plot firewall Policy usage
	plt.style.use('ggplot')

	ax = firewall_policies.plot(kind='bar', color="orange", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("Firewall Policies Usage - HISTORICAL", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/fw_policy_usage_historical.png', dpi='figure')
	logger.info(f"Historical Firewall POLICY Use Plot Saved")
	plt.pause(30)
	plt.close()
