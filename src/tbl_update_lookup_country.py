# New entries into lookup table will have a NULL COUNTRY value
# If source ip gets an ASN response, but no ALPHA-2 country code, 'notfound' is entered in db for that ip
# If country code is found, but code not in countries table, its ALPHA-2 code is entered into lookup table to resolve later
# Populated 'countries' table using file found on the web
# I exported my countries' table to the sample folder

import sqlalchemy as sa
import ipwhois
import my_secrets

engine = sa.create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
                                                                   my_secrets.dbhost, my_secrets.dbname))


# TODO how to create sa try/except?
def update():
    """Updates lookup table with unique ips from ALPHA-2 to full country name"""
    with engine.connect() as conn, conn.begin():
        sql = '''SELECT source, country from lookup WHERE country is Null;'''
        lookups = conn.execute(sql)

        for ip, country in lookups:
            # Try to get a response with country ALPHA2 via RDAP
            try:
                obj = ipwhois.IPWhois(ip)
                result = obj.lookup_rdap()
                if result['asn_country_code'] == '' or result['asn_country_code'] is None:
                    print(f"{ip} had no alpha2 code")
                    asn_alpha2 = 'notfound'
                    conn.execute(f'''update lookup SET country = 'notfound' WHERE SOURCE = '{ip}';''')

                else:
                    asn_alpha2 = result['asn_country_code'].lower()
                    country_lookup = conn.execute(f"SELECT name from countries WHERE alpha2 = '{asn_alpha2}';")
                    country = [n for n in country_lookup][0][0]
                    conn.execute(f'''update lookup SET country = '{country}' WHERE SOURCE = '{ip}';''')
                    print(f'country set to: {country} for ip {ip}')

            except (ValueError, AttributeError, ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError,
                    ipwhois.ASNParseError, ipwhois.ASNOriginLookupError, ipwhois.ASNRegistryError,
                    ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:
                print(str(e) + f" on {ip}.")
                conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')
                # continue

            # Try to get country name from ALPHA-2 country code
            # try:
            #     country_lookup = conn.execute(f"SELECT name from countries WHERE alpha2 = '{asn_alpha2}';")
            #     country = [n for n in country_lookup][0][0]
            #     conn.execute(f'''update lookup SET country = '{country}' WHERE SOURCE = '{ip}';''')
            #     print(f'country set to: {country} for ip {ip}')
            #
            # except Exception as e:
            #     print(str(e), f'***country name not found in countries DB for {ip}. Research*** ')
            #     conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')
            #     print(f'*******************asn_alpha2 {asn_alpha2} added for {ip}. Research Code*** ')
