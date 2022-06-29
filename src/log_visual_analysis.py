import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import my_secrets
from collections import Counter

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))


# TODO Analyze current processed log. Tweak Country, add time span to all plots?
def analyze(log):
	"""Takes log analysis data stored in databases and presents information to screen and file"""
	freq_ports = log.groupby(['DPT']).size()
	freq_ports_sorted = freq_ports.sort_values(ascending=False).head(15)
	freq_hostnames = log.groupby(['HOSTNAME']).size()
	freq_hostnames_sorted = freq_hostnames.sort_values(ascending=False).head(15)
	firewall_policies = log.groupby(['POLICY']).size()
	sources = log['SOURCE'].head(10)

	# plot Top 15 SOURCE countrys found accessing firewall
	top_countries = []
	with engine.connect() as conn, conn.begin():
		for source in sources:
			get_country = pd.read_sql(f'''SELECT COUNTRY FROM fwlogs.lookup where SOURCE = '{source}';''',
								con=conn, index_col='COUNTRY')
			get_country_list = list(get_country.index.values)
			top_countries.append(get_country_list.pop())
	counter_top_countries = Counter(top_countries)
	counter_no_country_name = {k: v for k, v in counter_top_countries.items() if len(k) < 2}
	# no_countries = [k for k,v in counter_top_countries.values() if (len(counter_top_countries.values()) == 2)]
	print(counter_no_country_name)

	# TOP Countries
	plt.style.use('ggplot')  # 'ggplot' 'classic'
	plt.bar(counter_top_countries.keys(), counter_top_countries.values())
	# ax = counter_top_countries.plot(kind='bar', color="indigo", fontsize=8)
	# print(ax)
	# ax.set_alpha(.8)
	# plt.set_title("TOP 15 SOURCE COUNTRIES", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	# ax.set_ylabel("Hits", fontsize=12)
	# ax.set_xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	# plt.savefig('../output/top_countries.png', dpi='figure')
	plt.pause(30)
	plt.close()

# 	# plot country ALPHA-2 codes that cannot map to country name
	plt.style.use('ggplot')  # 'ggplot' 'classic'
	plt.bar(counter_no_country_name.keys(), counter_no_country_name.values())
	# plt.bar(no_countries.keys(), no_countries.values())

	# ax = no_countries.plot(kind='bar', color="blue", fontsize=10)
	# ax.set_alpha(.2)
	# ax.set_title("COUNTRY ALPHA-2 NOT RESOLVED", fontsize=13)
	#
	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	# plt.savefig('../output/no_countries.png')
	plt.pause(30)
	plt.close()

# 	# plot frequent ports used coming into router
# 	plt.style.use('ggplot')  # 'ggplot' 'classic'
#
# 	ax = freq_ports_sorted.plot(kind='bar', color="green", fontsize=10)
# 	ax.set_alpha(.2)
# 	ax.set_title("TOP 15 Destination Ports", fontsize=13)
#
# 	plt.xticks(rotation=45, ha='right', va='center_baseline')
# 	plt.tight_layout()
#
# 	mng = plt.get_current_fig_manager()
# 	mng.window.showMaximized()
# 	plt.show(block=False)
# 	plt.savefig('../output/top_ports.png')
# 	plt.pause(30)
# 	plt.close()
#
# # 	# plot frequent hostnames coming into router
# 	plt.style.use('ggplot')  # 'ggplot' 'classic'
#
# 	ax = freq_hostnames_sorted.plot(kind='bar', color="red", fontsize=10)
# 	ax.set_alpha(.2)
# 	ax.set_title("TOP 15 HOSTNAMES", fontsize=12)
#
# 	plt.xticks(rotation=35, ha='right', va='center_baseline')
# 	plt.tight_layout()
#
# 	mng = plt.get_current_fig_manager()
# 	mng.window.showMaximized()
# 	plt.show(block=False)
# 	plt.savefig('../output/top_hostnames.png', dpi='figure')
# 	plt.pause(30)
# 	plt.close()
#
# # # plot firewall Policy usage
# 	plt.style.use('ggplot')  # 'ggplot' 'classic'
#
# 	ax = firewall_policies.plot(kind='bar', color="orange", fontsize=10)
# 	ax.set_alpha(.2)
# 	ax.set_title("Firewall Policies Usage", fontsize=12)
#
# 	plt.xticks(rotation=35, ha='right', va='center_baseline')
# 	plt.tight_layout()
#
# 	mng = plt.get_current_fig_manager()
# 	mng.window.showMaximized()
# 	plt.show(block=False)
# 	plt.savefig('../output/fw_policy_usage.png', dpi='figure')
# 	plt.pause(30)
# 	plt.close()
