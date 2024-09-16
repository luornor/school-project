from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class CustomAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        
        # Authenticate staff (e.g., administrator) using email
        try:
            user = UserModel.objects.get(email=username, role=UserModel.Roles.ADMINISTRATOR)
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            pass
        
        # Authenticate students using user_id
        try:
            user = UserModel.objects.get(user_id=username, role=UserModel.Roles.STUDENT)
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            pass
        
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
