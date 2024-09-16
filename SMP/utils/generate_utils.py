import random
# from twilio.rest import Client
from django.utils.crypto import get_random_string
import string
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
import secrets

def user_id():
    return ''.join(str(random.randint(0, 9)) for _ in range(8))


def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(length))
    return password




def generate_activation_code():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def send_verification_email(email,message,html_message):

    try:
        subject = 'Verify your email'
        from_email = settings.EMAIL_HOST_USER
        msg = EmailMultiAlternatives(
            subject=subject,
            body=message,
            from_email=from_email,
            to=[email],)
        msg.attach_alternative(html_message, 'text/html')
        msg.send()
    except Exception as e:
        print(f"Error sending email: {e}")
        raise e 

def generate_unique_email():
    return f'{get_random_string(length=8)}@example.com'

# def send_sms(phone_number, message):
#     account_sid = 'your_twilio_account_sid'
#     auth_token = 'your_twilio_auth_token'
#     client = Client(account_sid, auth_token)

#     message = client.messages.create(
#         body=message,
#         from_='+1234567890',  # Your Twilio number
#         to=phone_number
#     )

#     return message.sid
