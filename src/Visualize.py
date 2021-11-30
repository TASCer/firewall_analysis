import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl

# PANDAS SETUP
pd.set_option('max_colwidth', 800)
pd.set_option('display.max_rows', 500)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)


df = pd.DataFrame(rec, columns=('HITS', 'COUNTRY'))
totalHits = df['HITS'].count()
print(totalHits)
df_Groups = df.groupby(by='COUNTRY').count()
df_GroupsSorted = df_Groups.sort_values(by='HITS', ascending=False)
top15 = df_GroupsSorted.head(15)
# print(type(top15), top15.info())

# plt.ion()
plt.style.use('ggplot')  # 'ggplot' 'classic'
ax = top15.plot(kind='bar', color="indigo", fontsize=13)
ax.set_alpha(1.8)
ax.set_title("TOP 15 FIREWALL HITS by COUNTRY", fontsize=22)

plt.xticks(rotation=45, ha= 'right', va = 'center_baseline')

ax.set_ylabel("Hit Count", fontsize=15)

legend = ax.legend(loc='upper center', shadow=True, fontsize='x-large')

mng = plt.get_current_fig_manager()
mng.window.showMaximized()
plt.show(block=False)

# print(mpl.is_interactive())

plt.pause(45)
plt.close()
