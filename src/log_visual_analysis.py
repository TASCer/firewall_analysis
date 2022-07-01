import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import my_secrets
from collections import Counter

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))


# TODO Analyze current processed log. Tweak Country, add time span to all plots?
def analyze(log):
	"""Takes cureently processed log and presents information to screen and file"""
	freq_ports = log.groupby(['DPT']).size()
	freq_ports_sorted = freq_ports.sort_values(ascending=False).head(15)
	freq_hostnames = log.groupby(['HOSTNAME']).size()
	freq_hostnames_sorted = freq_hostnames.sort_values(ascending=False).head(15)
	firewall_policies = log.groupby(['POLICY']).size()
	sources = log['SOURCE']

# Get countrird for currently processed log
	top_countries = []
	with engine.connect() as conn, conn.begin():
		for source in sources:
			get_country = pd.read_sql(f'''SELECT COUNTRY FROM fwlogs.lookup where SOURCE = '{source}';''',
								con=conn, index_col='COUNTRY')
			get_country_list = list(get_country.index.values)
			top_countries.append(get_country_list.pop())
	counter_top_countries = Counter(top_countries)
	counter_no_country_name = {k: v for k, v in counter_top_countries.items() if len(k) < 2 or v == 'notfound'}
	# no_countries = [k for k,v in counter_top_countries.values() if (len(counter_top_countries.values()) == 2)]
	top_15_countries = counter_top_countries.most_common(15)

	print(top_15_countries, type(top_15_countries))

# Plot tOP Countries
	plt.style.use('ggplot')  # 'ggplot' 'classic'
	x, y = zip(*top_15_countries)
	plt.bar(x, y)
	plt.title("TOP 15 SOURCE COUNTRIES", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	plt.ylabel("Hits", fontsize=12)
	plt.xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_countries.png', dpi='figure')
	plt.pause(30)
	plt.close()

# plot SOURCE where country name cammot be determined
	plt.style.use('ggplot')  # 'ggplot' 'classic'
	plt.bar(counter_no_country_name.keys(), counter_no_country_name.values())
	plt.title("COUNTRY ALPHA-2 NOT RESOLVED", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/no_countries.png')
	plt.pause(30)
	plt.close()

# plot frequent ports used coming into router
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = freq_ports_sorted.plot(kind='bar', color="green", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 Destination Ports", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_ports.png')
	plt.pause(30)
	plt.close()

# plot frequent hostnames coming into router
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = freq_hostnames_sorted.plot(kind='bar', color="red", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 HOSTNAMES", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_hostnames.png', dpi='figure')
	plt.pause(30)
	plt.close()

	# plot firewall Policy usage
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = firewall_policies.plot(kind='bar', color="orange", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("Firewall Policies Usage", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/fw_policy_usage.png', dpi='figure')
	plt.pause(30)
	plt.close()
