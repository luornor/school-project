from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import(
StaffLoginSerializer, StudentLoginSerializer,StaffSerializer,
StudentSerializer, StaffRegisterSerializer, StudentRegistrationSerializer
)
from .backend import CustomAuthBackend
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from .models import CustomUser
from django.core.exceptions import ValidationError
from .models import EmailVerification
from utils.generate_utils import send_verification_email
from django.template.loader import render_to_string 
from django.utils.html import strip_tags



class RootAPIView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Root API Endpoint",
        operation_description="Provides the URLs for the available endpoints in the API.",
        responses={
            200: openapi.Response(
                'Successful operation',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                )
            )
        },
        tags=['Root']
    )
    def get(self, request, *args, **kwargs):
        api_urls = {
            'Staff Login': '/api/staff-login/',
            'Student Login': '/api/student-login/',
            'Staff Registration': '/api/staff-register/',
            'Student Registration': '/api/student-register/',
        }
        return Response(api_urls, status=status.HTTP_200_OK)


class StaffRegisterView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Staff Registration",
        operation_description="Register a new staff member using email, username, and password. A verification email will be sent.",
        request_body=StaffRegisterSerializer,
        responses={
            201: openapi.Response('Staff registered successfully. Verification email sent.'),
            400: openapi.Response('Invalid data')
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        serializer = StaffRegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()  # Save the user and get the instance
                user_data = StaffRegisterSerializer(user).data
                return Response({
                    'message': 'Staff registered successfully. A verification email has been sent.',
                    'user': user_data
                }, status=status.HTTP_201_CREATED)
            except ValidationError as e:
                # Catch validation errors from the serializer or email sending
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                # Catch any unexpected errors
                return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_summary="Verify Email",
        operation_description="Verifies the user's email address using a verification code sent via email. Marks the user as active if the code is valid.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'code': openapi.Schema(type=openapi.TYPE_STRING, description='Verification code sent to the user\'s email')
            },
            required=['code']
        ),
        responses={
            200: openapi.Response(
                description="Email verified successfully. User can now log in.",
                examples={
                    'application/json': {'message': 'Email verified successfully. You can now log in.'}
                }
            ),
            400: openapi.Response(
                description="Error occurred during verification, such as invalid code or expired code.",
                examples={
                    'application/json': {
                        'error': 'Invalid verification code.',
                        'message': 'Verification code has expired. Please try again.',
                        'message': 'Email already verified.'
                    }
                }
            )
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        try:
            code = request.data.get('code')  # Extract the verification code from the request

            # Find the verification entry using the code
            verification = EmailVerification.objects.get(code=code)

            # Check if the email has already been verified
            if verification.verified:
                return Response({'message': 'Email already verified.'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the verification code has expired
            if verification.is_expired():  # Assuming you have an `is_expired` method in your model
                return Response({'message': 'Verification code has expired. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)

            # Mark the user as active and email as verified
            user = verification.user
            verification.verified=True
            user.is_active = True
            user.save()

            # Delete the verification entry after successful verification
            verification.delete()

            return Response({'message': 'Email verified successfully. You can now log in.'}, status=status.HTTP_200_OK)

        except EmailVerification.DoesNotExist:
            return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_summary="Resend Email Verification Code",
        operation_description="Resend a verification code to the user's email address.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            },
            required=['email']
        ),
        responses={
            200: openapi.Response('Verification code has been resent.'),
            400: openapi.Response('Invalid request or user not found.'),
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)

            if user.is_active:
                return Response({'message': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)

            verification, created = EmailVerification.objects.get_or_create(user=user)

            # If the verification code exists but is expired, generate a new one
            if not created and verification.is_expired():
                verification.delete()  # Delete the old expired code
                verification = EmailVerification.objects.create(user=user)  # Generate a new code

            # Resend the email with the (new or existing) verification code
            context = {
            "verification_code": verification.code,
            }
            html_message = render_to_string("email_text.html", context)
            plain_message = strip_tags(html_message)
            send_verification_email(user.email, plain_message,html_message)  # Ensure this function sends the verification email

            return Response({'message': 'Verification code has been resent.'}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        

class StaffLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Staff Login",
        operation_description="Login for staff members using email and password.",
        request_body=StaffLoginSerializer,
        responses={
            200: openapi.Response('Staff logged in successfully'),
            400: openapi.Response('Invalid credentials or role')
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        serializer = StaffLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomAuthBackend().authenticate(
                request,
                username=serializer.validated_data['email'],
                password=serializer.validated_data['password']
            )
            if user is not None and user.role == user.Roles.ADMINISTRATOR:
                refresh = RefreshToken.for_user(user)
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
                return Response({
                    'message': 'Staff logged in successfully',
                    'access': str(refresh.access_token),
                    'user': user_data,
                    'refresh': str(refresh)
                    }, 
                    status=status.HTTP_200_OK)
            return Response({'error': 'Invalid credentials or role'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StaffDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get Staff by ID",
        operation_description="Retrieve staff member details by ID.",
        responses={
            200: StaffSerializer,
            404: "Staff not found"
        },
        tags=['User Management']
    )
    def get(self, request, user_id, *args, **kwargs):
        staff = get_object_or_404(CustomUser, id=user_id, role=CustomUser.Roles.ADMINISTRATOR)
        serializer = StaffSerializer(staff)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_summary="Update Staff Details",
        operation_description="Update staff member details.",
        request_body=StaffSerializer,
        responses={
            200: "Staff details updated successfully",
            400: "Invalid data",
            404: "Staff not found"
        },
        tags=['User Management']
    )
    def put(self, request, user_id, *args, **kwargs):
        staff = get_object_or_404(CustomUser, id=user_id, role=CustomUser.Roles.ADMINISTRATOR)
        serializer = StaffSerializer(staff, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StudentRegistrationView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Register Student",
        operation_description="Register a new student. Only authenticated staff members with the 'ADMINISTRATOR' role can perform this action. The system generates a user ID and password for the student.",
        request_body=StudentRegistrationSerializer,
        responses={
            201: openapi.Response('Student registered successfully', StudentRegistrationSerializer),
            400: openapi.Response('Bad request', openapi.Schema(type=openapi.TYPE_OBJECT)),
            403: openapi.Response('Forbidden - Not an administrator', openapi.Schema(type=openapi.TYPE_OBJECT)),
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        # Debugging: Check the user role
        print(f"Authenticated user role: {request.user.role}")
        
        if request.user.role != CustomUser.Roles.ADMINISTRATOR:
            return Response({'error': 'Only staff can register students'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = StudentRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            student = serializer.save()
            student_data = {
                'user_id': student.user.user_id,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'dob': student.dob,
                'phone_number': student.phone_number,
                'stage': student.stage,
                'enrollment_date': student.enrollment_date
            }
            return Response({
                'message': 'Student registered successfully',
                'student': student_data
            }, status=status.HTTP_201_CREATED)
        
        # Debugging: Print serializer errors
        print(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StudentLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Student Login",
        operation_description="Login for students using user ID and password.",
        request_body=StudentLoginSerializer,
        responses={
            200: openapi.Response(
                'Student logged in successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: openapi.Response('Invalid credentials or role')
        },
        tags=['User Management']
    )
    def post(self, request, *args, **kwargs):
        serializer = StudentLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomAuthBackend().authenticate(
                request,
                username=serializer.validated_data['user_id'],
                password=serializer.validated_data['password']
            )
            if user is not None and user.role == user.Roles.STUDENT:
                refresh = RefreshToken.for_user(user)
                user_serializer = StudentSerializer(user)
                return Response({
                    'message': 'Student logged in successfully',
                    'student': user_serializer.data,
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid credentials or role'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)