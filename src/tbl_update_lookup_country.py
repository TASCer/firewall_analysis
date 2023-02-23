import datetime as dt
import ipwhois
import logging
import my_secrets

from datetime import datetime
from ipwhois.utils import get_countries
from ipwhois import IPWhois
from logging import Logger
from sqlalchemy.engine import Engine, CursorResult
from sqlalchemy import exc, create_engine
from typing import Optional, Any

now: datetime = dt.datetime.now()
todays_date: str = now.strftime('%D').replace('/', '-')

COUNTRIES = get_countries()


def update() -> object:
    """Updates lookup table with unique ips from ALPHA-2 to full country name"""
    logger: Logger = logging.getLogger(__name__)
    try:
        engine: Engine = create_engine("mysql+pymysql://{0}:{1}@{2}/{3}".format(my_secrets.dbuser, my_secrets.dbpass,
                                                                        my_secrets.dbhost, my_secrets.dbname))
    except exc.SQLAlchemyError as e:
        logger.critical(str(e))
        engine = None
        exit()

    with engine.connect() as conn, conn.begin():
        try:
            sql: str = '''SELECT source, country from lookup WHERE COUNTRY is null or COUNTRY like '%%HTTP%%';'''  # like '%%HTTP%%' or COUNTRY = 'ZZ' or COUNTRY = 'unknown'
            lookups: CursorResult = conn.execute(sql)

        except exc.SQLAlchemyError as e:
            logger.warning(str(e))
            lookups = None
            exit()

        for ip, country in lookups:
            try:
                obj: IPWhois = ipwhois.IPWhois(ip, timeout=10)
                result: dict = obj.lookup_rdap()

            except (UnboundLocalError, ValueError, AttributeError, ipwhois.BaseIpwhoisException, ipwhois.ASNLookupError,
                    ipwhois.ASNParseError, ipwhois.ASNOriginLookupError, ipwhois.ASNRegistryError,
                    ipwhois.HostLookupError, ipwhois.HTTPLookupError) as e:

                result = None
                error: str = str(e).split('http:')[0]
                logger.error(f"{error} {ip}")

                conn.execute(f'''update lookup SET country = '{error}' WHERE SOURCE = '{ip}';''')
                continue

            asn_alpha2: str = result['asn_country_code']

            if asn_alpha2 is None or asn_alpha2 == '':
                logger.warning(f"{ip} had no alpha2 code, setting country name to 'unknown'")
                asn_alpha2: str = 'unknown'
                conn.execute(f'''update lookup SET country = '{asn_alpha2}' WHERE SOURCE = '{ip}';''')
                continue

            elif asn_alpha2.islower():
                asn_alpha2: str = asn_alpha2.upper()
                logger.warning(f'RDAP responded with lowercase country for {ip}, should be upper')

            else:
                country_name: Optional[Any] = COUNTRIES.get(asn_alpha2)

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
