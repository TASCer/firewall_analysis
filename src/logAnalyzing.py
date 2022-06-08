import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import mySecrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))


# TODO countries and hostnames issues - fix sizing
def analyze():
	with engine.connect() as conn, conn.begin():
		top_countries = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup group by COUNTRY order by hits desc;''',
							con=conn, index_col='COUNTRY')
		nocountry = pd.read_sql('''SELECT COUNTRY, count(*) as hits from lookup WHERE country is null or country = ''
							or country = 'notfound' or length(country) = 2 group by country order by hits desc;''',
							con=conn, index_col='COUNTRY')
		freq_ports = pd.read_sql('''SELECT DPT, count(DPT) as hits from activity group by DPT order by hits desc limit 15;''',
							con=conn, index_col='DPT')
		freq_hostnames = pd.read_sql('''SELECT HOSTNAME, count(HOSTNAME) as hits from activity WHERE HOSTNAME != '' group by HOSTNAME order by hits desc limit 15;''',
							con=conn, index_col='HOSTNAME')

	# plot Top 15 countrys in lookup table
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = top_countries[:14].plot(kind='bar', color="indigo", fontsize=8)
	# print(ax)
	ax.set_alpha(.8)
	ax.set_title("TOP 15 FIREWALL SOURCE COUNTRY", fontsize=22)

	plt.xticks(rotation=35, ha='right', va='center_baseline')

	ax.set_ylabel("Hits", fontsize=12)
	ax.set_xlabel("Country", fontsize=12)

	plt.tight_layout()
	plt.show(block=False)
	plt.savefig('../output/top_countries.png', dpi='figure')
	plt.pause(30)
	plt.close()

	# plot country codes that cannot map to country name
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = nocountry.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("COUNTRY NAME NOT RESOLVED", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()
	plt.show(block=False)
	plt.savefig('../output/no_countries.png')
	plt.pause(30)
	plt.close()

	# plot frequent ports coming into router
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = freq_ports.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 Destination Ports", fontsize=13)

	plt.xticks(rotation=45, ha='right', va='center_baseline')
	plt.tight_layout()
	plt.show(block=False)
	plt.savefig('../output/top_ports.png')
	plt.pause(30)
	plt.close()

	# plot frequent hostnames coming into router
	plt.style.use('ggplot')  # 'ggplot' 'classic'

	ax = freq_hostnames.plot(kind='bar', color="red", fontsize=6)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 HOSTNAMES", fontsize=12)

	plt.xticks(rotation=35, ha='right', va='center_baseline')
	plt.tight_layout()
	plt.show(block=False)
	plt.savefig('../output/top_hostnames.png', dpi='figure')
	plt.pause(30)
	plt.close()
