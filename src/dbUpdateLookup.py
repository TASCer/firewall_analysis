# Updates lookup table with unique ips to full country name
# If country code not found, "" entered into lookup table
# If country code is found, but code not in countries table, enter its ALPHA-2 code into lookup table to resolve later
# Populated countries table using file found on the web
# I exported my countries table to the sample folder


import sqlalchemy as sa
import ipwhois
import mySecrets
# from mailer import sendMail

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass,
                                                                   mySecrets.dbhost, mySecrets.dbname))

with engine.connect() as conn, conn.begin():
    sql = '''SELECT source, country from lookup WHERE country = '' or country is Null;'''
    lookups = conn.execute(sql)

    for ip, country in lookups:

        # Try to get a response
        try:
            obj = ipwhois.IPWhois(ip)
            result = obj.lookup_rdap()

        except (ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError, ipwhois.ASNParseError, ipwhois.ASNOriginLookupError,
                ipwhois.ASNRegistryError, ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
            msg = str(e)
            print(msg + " 1st EXCEPT: IPWhois lookup FAILED!", ip)
            continue

        # Try to get the country code
        try:
            countryRes = result['asn_country_code'].lower()

            if countryRes:
                print('got country response', countryRes)

            elif not countryRes:
                raise ValueError

        except (ValueError, AttributeError) as e:
            print("2nd EXCEPT: no country code found in asn", ip)
            continue

        # Try to get country name from country code
        try:
            countryRes = result['asn_country_code'].lower()
            countryLU = conn.execute(f"SELECT name from countries WHERE alpha2 = '{countryRes}';")
            country = [n for n in countryLU][0][0]
            conn.execute(f'''update lookup SET country = '{country}' WHERE SOURCE = '{ip}';''')

        except Exception as e:
            print('************3rd except: most likely country name not found. Research ISO code********** ', ip, e)
            conn.execute(f'''update lookup SET country = '{countryRes}' WHERE SOURCE = '{ip}';''')

