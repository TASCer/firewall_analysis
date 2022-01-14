# Updates lookup table ip to country names
# Initial lookup populated with LoadActivity deduped

import sqlalchemy as sa
# from ipwhois import IPWhois
import ipwhois
import mySecrets
from mailer import sendMail

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass, mySecrets.dbhost, mySecrets.dbname))

with engine.connect() as conn, conn.begin():
    sql = '''SELECT source, country from lookup WHERE country is null or country = '';'''
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
            sendMail("IPWhois lookup FAILED!", msg)

        # Try to get the country code
        try:
            countryRes = result['asn_country_code'].lower()

            if countryRes:
                print('got country response', countryRes)

            elif not countryRes:
                print("no country code found in asn", ip)
                conn.execute('''update lookup SET country = '{}' WHERE SOURCE = '{}';'''.format('notfound', ip))
                print("UPDATED DB with notfound")
                continue

        except (ValueError, AttributeError) as e:
            print("EXCEPTION: no country code found in asn", ip)
            sendMail("Country Code for IP not Found!", ip)

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
