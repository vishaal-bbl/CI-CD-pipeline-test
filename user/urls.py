from django.urls import path
from .views import (UserRegistration, UserLogin, TestAuthentication, UserUpdate, AdminRegistration,
UserManagementView, CreateUserProfileView, UpdateUserProfileView, UserForgotPasswordView, ResetPasswordView,
VerifyEmailView)

urlpatterns = [
    path('api/auth/register/', UserRegistration.as_view(), name='register'),
    path('api/auth/verifyemail/<uidb64>/<token>/', VerifyEmailView.as_view()),
    path('api/auth/login/', UserLogin.as_view(), name='login'),
    path('api/auth/forgotpassword/', UserForgotPasswordView.as_view()),
    path('api/auth/resetpassword/<uidb64>/<token>/', ResetPasswordView.as_view()),
    path('api/user/test/', TestAuthentication.as_view(), name='profile'),
    path('api/user/', UserUpdate.as_view(), name='update'),
    path('api/auth/register/admin/', AdminRegistration.as_view(), name='admin-register'),
    path('api/user/<uuid:pk>/', UserManagementView.as_view()),
    path('api/user/profile/', CreateUserProfileView.as_view(), name='create-profile'),
    path('api/user/profile/', UpdateUserProfileView.as_view(), name='update-profile'),
]
