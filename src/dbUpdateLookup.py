# If country ALPHA-2 code not found in ASN, '' is entered into lookup table
# If country code is found, but code not in countries table, its ALPHA-2 code is entered into lookup table to resolve later
# Populated 'countries' table using file found on the web
# I exported my countries' table to the sample folder


import sqlalchemy as sa
import ipwhois
import mySecrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(mySecrets.dbuser, mySecrets.dbpass,
                                                                   mySecrets.dbhost, mySecrets.dbname))


def update():
    """Updates lookup table with unique ips from ALPHA-2 to full country name"""
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
                print(msg + f" RDAP EXCEPT on {ip}")

            # Try to get a response via WHOIS
            try:
                obj = ipwhois.IPWhois(ip)
                result = obj.lookup_whois()

            except (ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError, ipwhois.ASNParseError, ipwhois.ASNOriginLookupError,
                    ipwhois.ASNRegistryError, ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
                msg = str(e)
                print(msg + f" Whois EXCEPT on {ip}")

            # Try to get the country code
            try:
                country_res = result['asn_country_code']
                # print('***', country_res, type(country_res))
                if country_res:
                    country_res = country_res.lower()

                elif country_res is None:
                    raise ValueError

            except (ValueError, AttributeError) as e:
                print(str(e), f"NO country code found in asn for {ip}")

            # Try to get country name from ALPHA-2 country code
            try:
                country_res = result['asn_country_code'].lower()
                country_lookup = conn.execute(f"SELECT name from countries WHERE alpha2 = '{country_res}';")
                country = [n for n in country_lookup][0][0]
                conn.execute(f'''update lookup SET country = '{country}' WHERE SOURCE = '{ip}';''')

            except Exception as e:
                print(str(e), f'***country name not found in countries DB for {country_res}. Research ISO codes*** ')
                conn.execute(f'''update lookup SET country = '{country_res}' WHERE SOURCE = '{ip}';''')
