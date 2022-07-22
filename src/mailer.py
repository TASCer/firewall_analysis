import logging
import my_secrets
import smtplib

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('../log.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

exchange_user = my_secrets.exchange_user
exchange_password = my_secrets.exchange_password
sent_from = exchange_user


def send_mail(subject, text):
    """Takes in strings for email subject and contents and sends the email"""
    message = 'Subject: {}\n\n{}'.format(subject, text)
    try:
        server = smtplib.SMTP('{}'.format(my_secrets.mailserver), 25)
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
