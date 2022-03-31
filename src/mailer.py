# BASE MAIL MODULE

import smtplib
import mySecrets

# smtp_handler = logging.handlers.SMTPHandler(mailhost=("exchange.tascs.local", 25),
#                                             fromaddr="PYTHON@tascs.local",
#                                             toaddrs="todd@tascs.local",
#                                             subject=u"main.py error!")

# logger = logging.getLogger()
# logger.addHandler(smtp_handler)

# EMAIL CREDS & PROPERTIES
exchange_user = mySecrets.exchange_user
exchange_password = mySecrets.exchange_password  # NOT NEEDED FOR INTERNAL SMTP test for external & auth
sent_from = exchange_user
to = ['todd@tascs.local', 'pi@tascs.test']


def send_mail(subject, text):
    message = 'Subject: {}\n\n{}'.format(subject, text)
    try:
        server = smtplib.SMTP('{}'.format(mySecrets.mailserver), 25)
        server.ehlo()
        server.sendmail(sent_from, to, message)
        server.close()
        print('Email sent!')

    except Exception as e:
        print(str(e))
        print('Something went wrong...')

# 4 TESTING # No workie on TEST domain until I add my IP to EXCHANGE
# send_mail('test', 'test email ran from mailer module, not imported')
