from django.contrib import admin
from .models import CustomUser, Student,EmailVerification

# CustomUserAdmin to customize the list display of CustomUser
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id','username', 'email', 'role', 'user_id', 'is_superuser', 'date_created')
    list_filter = ('role','is_staff', 'is_superuser')
    search_fields = ('username', 'email')
    ordering = ('-date_created',)

# StudentAdmin to customize the list display of Student
@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name', 'dob', 'stage', 'enrollment_date')
    list_filter = ('stage', 'enrollment_date')
    search_fields = ('user__username', 'first_name', 'last_name')
    ordering = ('-enrollment_date',)


@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    def email(self, obj):
        return obj.user.email
    
    list_display = ('email','code','verified', 'expiry_date')

