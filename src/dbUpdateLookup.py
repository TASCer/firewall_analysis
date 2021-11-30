# Updates lookup tbl of ip/country names
# Initial lookup populated with LoadActivity deduped
import time
import sqlalchemy as sa
import datetime as dt
from mailer import sendMail
from ipwhois import IPWhois
import ipwhois
import mySecrets

# pd.set_option('display.max_columns', None)

# date for filenames
todaysDate = dt.datetime.now()
TD = todaysDate.strftime('%D').replace('/', '-')
# print(TD)

# JOB TIMER
nnstart = time.perf_counter()
print('FW lookup table updated country name STARTED')
sendMail("Firewall lookup table DB UPDATING Started", "Time Stamp: {}".format(dt.datetime.now()))

noCountryMSG = "NotFound"

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))

with engine.connect() as conn, conn.begin():
    sql = '''SELECT source, country from lookup WHERE country is null or country = '' or country = 'NOTFOUND';'''
    lookups = conn.execute(sql)
    for ip, country in lookups:
        # Try to get a response
        try:
            obj = ipwhois.IPWhois(ip)
            result = obj.lookup_rdap()
        except (ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError, ipwhois.ASNParseError, ipwhois.ASNOriginLookupError,
                ipwhois.ASNRegistryError, ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
            msg = str(e)
            print(msg + " IPWhois lookup FAILED!", ip)
            # sendMail("IPWhois lookup FAILED!", msg)

        # Try to get the country code
        try:
            countryRes = result['asn_country_code'].lower()
            # print(countryRes, type(countryRes))
            if countryRes:
                print('got country response', countryRes)

            else:
                print("no country code found in asn", ip)
                conn.execute('''update lookup SET country = '{}' WHERE SOURCE = '{}';'''.format(noCountryMSG, ip))  # NOT WORKING, ,making empty str


        except (ValueError, AttributeError) as e:
            print("no country code found in asn", ip)

        # Try to get country name from country code
        try:
            countryRes = result['asn_country_code'].lower()
            countryLU = conn.execute("SELECT name from countries WHERE alpha2 = '{}';".format(countryRes))
            country = [n for n in countryLU][0][0]
            print(country)
            conn.execute('''update lookup SET country = '{}' WHERE SOURCE = '{}';'''.format(country, ip))

        except Exception as e:
            print('************2nd except!! most likely country name not found research ISO code********** ', e)
            conn.execute('''update lookup SET country = '{}' WHERE SOURCE = '{}';'''.format(countryRes, ip))


nend = time.perf_counter()
print('FW lookup table updated country name ENDED')
elapsedTime = int(nend - nnstart)
print("***Elapsed Time*** (seconds): ", elapsedTime, type(elapsedTime))
sendMail("Firewall lookup table DB UPDATING Complete", "Time Elapsed (secs): {}".format(elapsedTime))
