import datetime as dt
import logging
from datetime import datetime
from logging import Logger
from smtplib import SMTP

import my_secrets
import smtplib

now: datetime = dt.datetime.now()
todays_date: str = now.strftime('%D').replace('/', '-')

logger: Logger = logging.getLogger(__name__)

exchange_user: str = my_secrets.exchange_user
exchange_password: str = my_secrets.exchange_password
sent_from: str = exchange_user


def send_mail(subject: str, text: str) -> None:
    """Takes in strings for email subject and contents and sends the email"""
    message: str = 'Subject: {}\n\n{}'.format(subject, text)
    try:
        server: SMTP = smtplib.SMTP('{}'.format(my_secrets.mailserver), 25)
        if server:
            server.ehlo()
            server.sendmail(sent_from, my_secrets.to, message)
            server.close()
            logger.info('Email sent!')
        else:
            raise ConnectionRefusedError

    except ConnectionRefusedError as e:
        logger.exception(f'Email NOT sent! {e}')

# 4 TESTING # No workie on TEST domain until I add my IP to EXCHANGE
# send_mail('test', 'test email ran from mailer module, not imported')
