import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import my_secrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass, my_secrets.dbhost, my_secrets.dbname))


def analyze():
	"""Takes log analysis data stored in databases and presents information to screen and file"""
	with engine.connect() as conn, conn.begin():
		top_countries = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup group by COUNTRY order by hits desc;''',
							con=conn, index_col='COUNTRY')
		nocountry = pd.read_sql('''SELECT COUNTRY, count(*) as hits from lookup WHERE country is null or country = ''
							or length(country) = 2 group by country order by hits desc;''',
							con=conn, index_col='COUNTRY')
		freq_ports = pd.read_sql('''SELECT DPT, count(DPT) as hits from activity group by DPT order by hits desc limit 15;''',
							con=conn, index_col='DPT')
		freq_hostnames = pd.read_sql('''SELECT HOSTNAME, count(HOSTNAME) as hits from activity WHERE HOSTNAME != '' group by HOSTNAME order by hits desc limit 15;''',
							con=conn, index_col='HOSTNAME')

	# plot Top 15 SOURCE countrys found accessing firewall
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = top_countries[:14].plot(kind='bar', color="indigo", fontsize=8)
	# print(ax)
	ax.set_alpha(.8)
	ax.set_title("TOP 15 SOURCE COUNTRIES", fontsize=10)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	ax.set_ylabel("Hits", fontsize=12)
	ax.set_xlabel("Country", fontsize=12)

	plt.tight_layout()
	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.savefig('../output/top_countries.png', dpi='figure')
	plt.pause(30)
	plt.close()

	# plot country ALPHA-2 codes that cannot map to country name
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = nocountry.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("COUNTRY ALPHA-2 NOT RESOLVED", fontsize=13)

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

	ax = freq_ports.plot(kind='bar', color="green", fontsize=10)
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

	ax = freq_hostnames.plot(kind='bar', color="red", fontsize=10)
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
