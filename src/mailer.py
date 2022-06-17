import smtplib
import mySecrets

exchange_user = mySecrets.exchange_user
exchange_password = mySecrets.exchange_password
sent_from = exchange_user
to = ['todd@tascs.local', 'pi@tascs.test']


def send_mail(subject, text):
    """Takes in strings for email subject and contents and sends the email"""
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
