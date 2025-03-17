import uuid
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken
# Create your models here.

class UserManager(BaseUserManager):

    def create_user(self,username, email, first_name, last_name, password=None, **extra_fields):
        if not username:
            raise ValueError("User must have a username")
        if not email:
            raise ValueError("User must have an email")

        user = self.model(username=username, email=self.normalize_email(email), first_name=first_name,last_name=last_name, **extra_fields)
        user.set_password(password) #Hashing Password

        user.save()
        return user

    def create_superuser(self,username, email,  first_name, last_name,password=None, **extra_fields):
        if not username:
            raise ValueError("User must have a username")
        if not email:
            raise ValueError("User must have an email")

        user = self.create_user(username=username, email=self.normalize_email(email), first_name=first_name,last_name=last_name, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.set_password(password) #Hashing Password

        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=50, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    def token(self):
        refresh = RefreshToken.for_user(self)

        return {
            'refresh':str(refresh),
            'access':str(refresh.access_token)
        }

class UserProfile(models.Model):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4())
    user = models.OneToOneField(User, blank=True, null=True, on_delete=models.CASCADE)
    bio = models.TextField(max_length=700, blank=True, null=True)
    phone_number = models.CharField(max_length=10, blank=True, null=True)
    profile_image = models.ImageField(
        upload_to="profile_pictures/",
        default="profile_pictures/user-default.png",
        blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Profile."