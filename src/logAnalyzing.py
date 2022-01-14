import pandas as pd
import sqlalchemy as sa
import matplotlib.pyplot as plt
import matplotlib as mpl
import mySecrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))

with engine.connect() as conn, conn.begin():
	lookupDF = pd.read_sql('''SELECT COUNTRY, count(*) as hits FROM fwlogs.lookup group by COUNTRY order by hits desc;'''
						, con=conn)
	nocountryDF = pd.read_sql('''SELECT * from lookup WHERE country is null or country = ''
								or country = 'notfound' or length(country) = 2;'''
						, con=conn)

print(nocountryDF)
print(lookupDF.head(15))

# totalHits = df['HITS'].count()
# print(totalHits)
# df_Groups = df.groupby(by='COUNTRY').count()
# df_GroupsSorted = df_Groups.sort_values(by='HITS', ascending=False)
# top15 = df_GroupsSorted.head(15)
# # print(type(top15), top15.info())
#
# plt.ion()
plt.style.use('ggplot')  # 'ggplot' 'classic'
ax = lookupDF[:14].plot(kind='bar', color="indigo", fontsize=13)
ax.set_alpha(.8)
ax.set_title("TOP 15 FIREWALL COUNTRY", fontsize=22)

plt.xticks(rotation=45, ha= 'right', va = 'center_baseline')

ax.set_ylabel("Hit Count", fontsize=15)

legend = ax.legend(loc='upper center', shadow=True, fontsize='x-large')

mng = plt.get_current_fig_manager()
mng.window.showMaximized()
plt.show(block=False)

# print(mpl.is_interactive())

plt.pause(45)
plt.close()
