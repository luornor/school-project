from rest_framework import serializers
from .models import CustomUser, Student
from utils.generate_utils import (
generate_password, generate_unique_email,
generate_activation_code,send_verification_email
)
from .models import EmailVerification
from django.template.loader import render_to_string 
from django.utils.html import strip_tags
from django.core.exceptions import ValidationError
import logging
from smtplib import SMTPException
logger = logging.getLogger(__name__)

class StaffLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class StudentLoginSerializer(serializers.Serializer):
    user_id = serializers.CharField()
    password = serializers.CharField(write_only=True)


class StaffRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id','email', 'username', 'password','role','date_created']
        read_only_fields = ['role', 'date_created']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        validated_data['role'] = CustomUser.Roles.ADMINISTRATOR
        user = CustomUser.objects.create_user(**validated_data)
        # Generate verification code
        verification_code = generate_activation_code()
        # Save the verification code to the database
        EmailVerification.objects.create(user=user, code=verification_code)
        context = {
            "verification_code": verification_code,
        }
        html_message = render_to_string("email_text.html", context)
        plain_message = strip_tags(html_message)
        # Send verification email
        try:
            # Send verification email
            send_verification_email(user.email, plain_message,html_message) 
        except SMTPException as e:
            # Handle SMTP errors (like email server errors)
            logger.error(f"SMTPException: Failed to send verification email to {user.email}. Error: {e}")
            raise ValidationError("There was an error sending the verification email. Please try again later.")
        except ConnectionError as e:
            # Handle connectivity issues (like no internet)
            logger.error(f"ConnectionError: Unable to connect to email server. Error: {e}")
            raise ValidationError("Unable to send email due to network issues. Please check your internet connection.")
        except Exception as e:
            # Catch all other exceptions
            logger.error(f"Exception: Failed to send verification email to {user.email}. Error: {e}")
            raise ValidationError("An unexpected error occurred. Please try again later.")
        return user
    

class StaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username','email', 'role']
        read_only_fields = ['id','role']  


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['user_id', 'username','user_id','email', 'role']
        read_only_fields = ['user_id','role']  


class StudentRegistrationSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    dob = serializers.DateField(required=True)
    phone_number = serializers.CharField(required=False)
    stage = serializers.CharField(required=False)

    class Meta:
        model = Student
        fields = ['first_name', 'last_name', 'dob', 'phone_number', 'stage']

    def create(self, validated_data):
        # Generate user ID and password
        password = generate_password()
        # Generate a unique placeholder email for students
        email = generate_unique_email()

        # Create the CustomUser instance
        user = CustomUser.objects.create_user(
            username=validated_data['first_name'],  # Simplified username generation
            email=email,  # Student may not have an email
            role=CustomUser.Roles.STUDENT,
            password=password
        )
        user.is_active = True
        user.save()
        # Create the Student instance
        student = Student.objects.create(
            user=user,
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            dob=validated_data['dob'],
            phone_number=validated_data.get('phone_number', ''),
            stage=validated_data.get('stage', '')
        )

        # Send the credentials to the student's phone number (or email if available)
        # Example sending logic (use Twilio for SMS or send_mail for email)
        print(f'Student registered: ID={user.user_id}, Password={password}')


        return student
