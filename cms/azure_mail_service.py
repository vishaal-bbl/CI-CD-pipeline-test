from azure.communication.email import EmailClient
from cms.settings.base import AZURE_MAIL_URL

POLLER_WAIT_TIME = 10

def send_azure_mail(subject, html_body, from_email, to_email):
    try:
        connection_string = AZURE_MAIL_URL
        email_client = EmailClient.from_connection_string(connection_string)

        message = {
            'senderAddress': from_email,
            'recipients': {
                'to': [{'address': to_email}]
            },
            'content': {'subject': subject, 'html':html_body, 'plain_text':html_body}
        }

        poller = email_client.begin_send(message)

        time_elapsed = 0
        while not poller.done():
            print('Email send poller statues: '+ poller.status())

            poller.wait(POLLER_WAIT_TIME)
            time_elapsed += POLLER_WAIT_TIME

            if time_elapsed > 18*POLLER_WAIT_TIME:
                raise RuntimeError('Polling timed out.')

        if poller.result()['status'] == 'Succeeded':
            print(
                f"Successfully sent the email (operation id: {poller.result()['id']})"
            )
        else:
            raise RuntimeError(str(poller.result()["error"]))


    except Exception as ex:
        print(f'Error occurred: {ex}')  # Log the error
        raise Exception('Failed to send mail using Azure' + str(ex))

