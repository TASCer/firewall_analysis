import logging
import matplotlib.pyplot as plt
import my_secrets
import pandas as pd

from collections import Counter
from sqlalchemy import create_engine, exc

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('../log.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)


# TODO Non-historical No Country issue: logged error != plot count.
def analyze(log, timespan):
	"""Takes cureently processed log and presents information to screen and file"""
	timespan = timespan.split('.')[0].replace('\\', '')

	try:
		engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
																		my_secrets.dbhost, my_secrets.dbname))

	except exc.SQLAlchemyError as e:
		logger.critical(str(e))
		engine = None
		exit()

	freq_ports = log.groupby(['DPT']).size()
	freq_ports_sorted = freq_ports.sort_values(ascending=False).head(15)
	freq_hostnames = log.groupby(['HOSTNAME']).size()
	freq_hostnames_sorted = freq_hostnames.sort_values(ascending=False).head(15)
	firewall_policies = log.groupby(['POLICY']).size()
	sources = log['SOURCE']

# Get countries for currently processed log
	top_countries = []
	no_country = []
	with engine.connect() as conn, conn.begin():
		for source in sources:
			get_country = pd.read_sql(f'''SELECT COUNTRY FROM fwlogs.lookup where SOURCE = '{source}';''',
								con=conn)
			country = get_country.values[0][0]
			if len(country) == 2 or country.startswith('HTTP') or country == '' or country == 'unknown':
				no_country.append(country)
			top_countries.append(country)

	counter_top_countries = Counter(top_countries)
	counter_no_country = Counter(no_country)
	top_15_countries = counter_top_countries.most_common(15)


# Plot Top Countries
	plt.style.use('ggplot')
	x, y = zip(*top_15_countries)
	plt.bar(x, y)
	plt.title(f"TOP SOURCE COUNTRIES For: {timespan}", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	plt.ylabel("Hits", fontsize=12)
	plt.xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_countries.png', dpi='figure')
	logger.info("Top 15 Source Countries Plot Saved")
	plt.pause(30)
	plt.close()

# plot SOURCE where country name cammot be determined
	plt.style.use('ggplot')
	plt.bar(counter_no_country.keys(), counter_no_country.values())
	plt.title(f"COUNTRY ALPHA-2 NOT RESOLVED For: {timespan}", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/no_countries.png')
	logger.info(f"No Country Name Found Plot Saved")
	plt.pause(30)
	plt.close()

# plot frequent ports used coming into router
	plt.style.use('ggplot')

	ax = freq_ports_sorted.plot(kind='bar', color="green", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title(f"TOP 15 Destination Ports For: {timespan}", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_ports.png')
	logger.info(f"Top 15 Ports Plot Saved")
	plt.pause(30)
	plt.close()

# plot frequent hostnames coming into router
	plt.style.use('ggplot')

	ax = freq_hostnames_sorted.plot(kind='bar', color="red", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title(f"TOP 15 HOSTNAMES For: {timespan}", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_hostnames.png', dpi='figure')
	logger.info(f"Top 15 HOSTNAMES Plot Saved")
	plt.pause(30)
	plt.close()

# plot firewall Policy usage
	plt.style.use('ggplot')

	ax = firewall_policies.plot(kind='bar', color="orange", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title(f"Firewall Policies Usage For: {timespan}", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/fw_policy_usage.png', dpi='figure')
	logger.info(f"Firewall POLICY Use Plot Saved")
	plt.pause(30)
	plt.close()
