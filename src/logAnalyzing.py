import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import mySecrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))


def analyze():
	with engine.connect() as conn, conn.begin():
		lookup = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup group by COUNTRY order by hits desc;''',
							con=conn, index_col='COUNTRY')
		nocountry = pd.read_sql('''SELECT COUNTRY, count(*) as hits from lookup WHERE country is null or country = '' 
							or country = 'notfound' or length(country) = 2 group by country order by hits desc;''',
							con=conn, index_col='COUNTRY')
		freq_ports = pd.read_sql('''SELECT DPT, count(DPT) as hits from activity group by DPT order by hits desc limit 15;''',
							con=conn, index_col='DPT')

	# plot Top 15 countrys in lookup table

	plt.style.use('ggplot')  # 'ggplot' 'classic'
	ax = lookup[:14].plot(kind='bar', color="indigo", fontsize=13)
	ax.set_alpha(.8)
	ax.set_title("TOP 15 FIREWALL SOURCE COUNTRY", fontsize=22)

	plt.xticks(rotation=45, ha='right', va='center_baseline')

	ax.set_ylabel("Hit Count", fontsize=15)
	ax.set_xlabel("Country", fontsize=15)

	legend = ax.legend(loc='upper center', shadow=True, fontsize='x-large')

	mng = plt.get_current_fig_manager()
	mng.window.showMaximized()
	plt.show(block=False)
	plt.pause(30)
	plt.close()

	# plot country codes that cannot map to country name

	plt.style.use('ggplot')  # 'ggplot' 'classic'
	ax = nocountry.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("COUNTRY NAME NOT RESOLVED", fontsize=13)
	plt.xticks(rotation=45, ha='right', va='center_baseline')

	plt.show(block=False)
	plt.pause(30)
	plt.close()

	plt.style.use('ggplot')  # 'ggplot' 'classic'
	ax = freq_ports.plot(kind='bar', color="blue", fontsize=10)
	ax.set_alpha(.2)
	ax.set_title("TOP 15 Destination Ports", fontsize=13)
	plt.xticks(rotation=45, ha='right', va='center_baseline')

	plt.show(block=False)
	plt.pause(30)
	plt.close()
