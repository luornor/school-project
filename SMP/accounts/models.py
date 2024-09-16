from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from utils.generate_utils import user_id
from django.utils import timezone
from datetime import timedelta


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, role=None, password=None):
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            role=role,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email=email,
            username=username,
            role=CustomUser.Roles.ADMINISTRATOR,  # Ensure superuser has the correct role
            password=password,
        )
        user.is_staff = True  # Mark the user as staff
        user.is_active = True
        user.is_superuser = True  # Mark the user as superuser
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser):
    class Roles(models.TextChoices):
        ADMINISTRATOR = 'administrator'
        STUDENT = 'student'
        
    role = models.CharField(max_length=20, choices=Roles.choices, default=Roles.STUDENT, blank=True, null=True)
    email = models.EmailField(verbose_name='email address', max_length=255, unique=True, null=True, blank=True)
    user_id = models.CharField(max_length=10, default=user_id, unique=True)
    username = models.CharField(max_length=255, unique=True)
    date_created = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)  # Add this field
    is_superuser = models.BooleanField(default=False)  # Add this field

    objects = CustomUserManager()

    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True




class Student(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='student_profile')
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255,blank=True, null=True)
    dob = models.DateField()
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    stage = models.CharField(max_length=10,blank=True, null=True)
    enrollment_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f'{self.first_name} - {self.stage}'


class EmailVerification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,related_name='email_verification')
    code = models.CharField(max_length=32, unique=True)
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expiry_date =  models.DateTimeField(default=timezone.now() + timedelta(minutes=15))

    def __str__(self):
        return self.user.email
    
    def is_expired(self):
        return timezone.now() > self.expiry_date