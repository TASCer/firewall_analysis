# Updates lookup table with unique ips to full country name
# If country code not found, "" entered into lookup table
# If country code is found, but code not in countries table, enter its ALPHA-2 code into lookup table to resolve later
# Populated countries table using file found on the web
# I exported my countries table to the sample folder


import sqlalchemy as sa
import ipwhois
import mySecrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass,
                                                                   mySecrets.dbhost, mySecrets.dbname))


def update():

    with engine.connect() as conn, conn.begin():
        sql = '''SELECT source, country from lookup WHERE country is Null;'''
        lookups = conn.execute(sql)

        for ip, country in lookups:

            # Try to get a response via RDAP
            try:
                obj = ipwhois.IPWhois(ip)
                result = obj.lookup_rdap()

            except (ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError, ipwhois.ASNParseError, ipwhois.ASNOriginLookupError,
                    ipwhois.ASNRegistryError, ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
                msg = str(e)
                print(msg + " 1st EXCEPT: RDAP lookup FAILED!", ip)


            # Try to get a response via WHOIS
            try:
                obj = ipwhois.IPWhois(ip)
                result = obj.lookup_whois(ip)

            except (ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError, ipwhois.ASNParseError, ipwhois.ASNOriginLookupError,
                    ipwhois.ASNRegistryError, ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
                msg = str(e)
                print(msg + " 2nd EXCEPT: WHOIS lookup FAILED!", ip)


            # Try to get the country code
            try:
                country_res = result['asn_country_code']
                # print('***', country_res, type(country_res))
                if country_res:
                    country_res = country_res.lower()
                    print('got country response', country_res, ip)

                elif country_res is None:
                    raise ValueError

            except (ValueError, AttributeError) as e:
                print("3rd EXCEPT: no country code found in asn", ip, str(e))


            # Try to get country name from country code
            try:
                country_res = result['asn_country_code'].lower()
                country_lookup = conn.execute(f"SELECT name from countries WHERE alpha2 = '{country_res}';")
                country = [n for n in country_lookup][0][0]
                conn.execute(f'''update lookup SET country = '{country}' WHERE SOURCE = '{ip}';''')

            except Exception as e:
                print('************4th except: most likely country name not found. Research ISO code********** ', ip, e)
                conn.execute(f'''update lookup SET country = '{country_res}' WHERE SOURCE = '{ip}';''')
