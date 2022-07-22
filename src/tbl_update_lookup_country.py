# New entries into lookup table will have a NULL COUNTRY value
# If source ip gets an ASN response, but no ALPHA-2 country code, 'notfound' is entered as Country name in db for that ip
# If country code is found, but code not in countries table, its ALPHA-2 code is entered into lookup table to resolve later
# Populated 'countries' table using file found on the web
# I exported my countries' table to the sample folder

import ipwhois
import logging
import my_secrets

from sqlalchemy import exc, create_engine
from ipwhois.utils import get_countries

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('./log.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

COUNTRIES = get_countries()


# TODO Create sa try/except look at 1pwhois countries
def update():
    """Updates lookup table with unique ips from ALPHA-2 to full country name"""
    try:
        engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
                                                                        my_secrets.dbhost, my_secrets.dbname))
    except exc.SQLAlchemyError as e:
        logger.critical(str(e))
        engine = None
        exit()

    with engine.connect() as conn, conn.begin():
        try:
            sql = '''SELECT source, country from lookup WHERE COUNTRY is Null;'''
            lookups = conn.execute(sql)

        except exc.SQLAlchemyError as e:
            logger.warning(str(e))
            lookups = None

        for ip, country in lookups:
            # Try to get a response with country ALPHA2 via RDAP
            try:
                obj = ipwhois.IPWhois(ip)
                result = obj.lookup_rdap()
            except (UnboundLocalError, ValueError, AttributeError, ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError,
                    ipwhois.ASNParseError, ipwhois.ASNOriginLookupError, ipwhois.ASNRegistryError,
                    ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:

                logger.warning(f"{str(e)}")
                conn.execute(f'''update lookup SET country = 'error' WHERE SOURCE = '{ip}';''')

            if result['asn_country_code'] == '' or result['asn_country_code'] is None:
                logger.warning(f"{ip} had no alpha2 code")
                asn_alpha2 = 'notfound'
                conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')

            elif result['asn_country_code']:
                asn_alpha2 = result['asn_country_code']
                if asn_alpha2.islower():
                    logger.warning(f'RDAP responded with lowercase country for {ip}, should be upper')
                    asn_alpha2 = asn_alpha2.upper()
                country_name = COUNTRIES.get(asn_alpha2)
                if not country_name:
                    logger.warning("Country Name not found in COUNTRIES, setting it to alpha-2")
                    conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')

                else:
                    if "'" in country_name:
                        logger.info(f"{country_name} has an aposterphe")
                        country_name =country_name.replace("'", "''")
                        logger.warning(f"Apostrophe found in {country_name}")
                    conn.execute(f'''update lookup SET country = '{country_name}' WHERE SOURCE = '{ip}';''')
