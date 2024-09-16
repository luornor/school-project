from django.urls import path
from .views import (
RootAPIView, StaffLoginView, StudentLoginView, StaffRegisterView, 
StudentRegistrationView, StaffDetailView,VerifyEmailView,
ResendVerificationEmailView
) 

urlpatterns = [
    path('', RootAPIView.as_view(), name='root-api'),
    path('staff-register/', StaffRegisterView.as_view(), name='staff_register'),
    path('staff-login/', StaffLoginView.as_view(), name='staff_login'),
    path('staff/<int:id>/', StaffDetailView.as_view(), name='staff_details'),
    path('student-login/', StudentLoginView.as_view(), name='student_login'),
    path('student-register/', StudentRegistrationView.as_view(), name='student_register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend_verification'),

]
