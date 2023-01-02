import datetime as dt
import ipwhois
import logging
import my_secrets

from ipwhois.utils import get_countries
from sqlalchemy import exc, create_engine

now = dt.datetime.now()
todays_date = now.strftime('%D').replace('/', '-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(f'../log_{todays_date}.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

COUNTRIES = get_countries()


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
            sql = '''SELECT source, country from lookup WHERE COUNTRY is null;'''  # like '%%HTTP%%'  = 'unknown'
            lookups = conn.execute(sql)

        except exc.SQLAlchemyError as e:
            logger.warning(str(e))
            lookups = None
            exit()

        for ip, country in lookups:
            # Try to get a response
            try:
                obj = ipwhois.IPWhois(ip, timeout=10)
                result = obj.lookup_rdap()

            except (UnboundLocalError, ValueError, AttributeError, ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError,
                    ipwhois.ASNParseError, ipwhois.ASNOriginLookupError, ipwhois.ASNRegistryError,
                    ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:

                result = None
                error = str(e).split('http:')[0]
                logger.error(f"{error} {ip}")

                conn.execute(f'''update lookup SET country = '{error}' WHERE SOURCE = '{ip}';''')
                continue

            asn_alpha2 = result['asn_country_code']

            if asn_alpha2 is None or asn_alpha2 == '':
                logger.warning(f"{ip} had no alpha2 code, setting country name to 'unknown'")
                asn_alpha2 = 'unknown'
                conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')
                continue

            elif asn_alpha2.islower():
                asn_alpha2 = asn_alpha2.upper()
                logger.warning(f'RDAP responded with lowercase country for {ip}, should be upper')

            else:
                country_name = COUNTRIES.get(asn_alpha2)

            if not country_name:
                logger.warning("Country Name not found in COUNTRIES, setting it to alpha-2")
                conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')
                continue

            elif "'" in country_name:
                country_name = country_name.replace("'", "''")
                logger.warning(f"Apostrophe found in {country_name}")
                conn.execute(f'''update lookup SET country = '{country_name}' WHERE SOURCE = '{ip}';''')

            else:
                conn.execute(f'''update lookup SET country = '{country_name}' WHERE SOURCE = '{ip}';''')
