from django.shortcuts import render
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from cms.azure_mail_service import send_azure_mail
from django.core.mail import EmailMessage
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from cms.settings.base import AZURE_SENDER_ADDRESS, EMAIL_HOST_USER
from django.contrib.auth.tokens import default_token_generator
from rest_framework import generics, status
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, UpdateUserSerializer, AdminRegisterSerializer, UserManagementSerializer, CreateUserProfileSerializer, UpdateUserProfileSerializer
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination

from .models import User, UserProfile
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import os
#from decouple import config

# Create your views here.

class UserRegistration(generics.CreateAPIView):

    serializer_class = RegisterSerializer

    def create(self, request):
        serilaizer = RegisterSerializer(data=request.data)

        #is_valid calls the seriallizer's validate method
        serilaizer.is_valid(raise_exception=True)
        serilaizer.save()

        email = request.data.get("email")

        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        verify_url = f'http://localhost:8000/api/auth/verifyemail/{uid}/{token}'
        html_content = render_to_string(
            "register_user_email.html", {"verify_url": verify_url}
        )
        subject = 'Verify your email'
        from_mail = AZURE_SENDER_ADDRESS

        send_azure_mail(subject, html_content, from_mail, email)

        # from_mail = settings.EMAIL_HOST_USER
        # email_message = EmailMessage(subject, html_content,from_mail,[email])

        # email_message.content_subtype = "html"  # Indicate that the email content is HTML
        # email_message.send()

        return Response(
            {'message':'User Registered successfully. Verify your e-mail to access your account, verification mail has been sent to your mail ID', 'verify_url':f'{verify_url}'}, status=status.HTTP_201_CREATED)

class VerifyEmailView(APIView):

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                try:
                    user_email = user.email
                    html_content = render_to_string(
                "verified_user_notification.html", {"user_email": user_email}
            )
                    subject = 'Activate User'
                    from_mail = AZURE_SENDER_ADDRESS
                    to_email = EMAIL_HOST_USER

                    send_azure_mail(subject, html_content, from_mail, to_email)
                    return Response(
                        {'message':'You have Verified, please wait for the internal team to activate your account.'}, status=status.HTTP_200_OK
                    )
                except Exception:
                    return Response(
                        {'message':'Failed to send Verification mail to the admin.'}
                    )

        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
            return Response(
                {"message": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST
            )


class AdminRegistration(generics.CreateAPIView):
    serializer_class = AdminRegisterSerializer

    def validate(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogin(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TestAuthentication(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'auth_key',
                openapi.IN_QUERY,
                description="Authentication key",
                type=openapi.TYPE_STRING,
            )
        ],
        responses={
            200: "User is Authorized",
            400: "Bad Request, Invalid User",
        }
    )

    def get(self, request):
        data={
            'msg': 'User Authenticated'
        }
        return Response(data, status=status.HTTP_200_OK)

class UserUpdate(generics.RetrieveUpdateAPIView):

    queryset = User.objects.all()
    serializer_class = UpdateUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data, status=status.HTTP_200_OK)

class UserManagementView(generics.RetrieveUpdateDestroyAPIView):

    queryset = User.objects.filter(is_superuser=False)
    serializer_class = UserManagementSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user_id = self.kwargs.get('pk')
        print(user_id)
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class CustomPageNumberPagination(PageNumberPagination):
    page_size = os.environ.get('PAGE_SIZE')
    page_query_param = os.environ.get('PAGE_QUERY_PARAM')

class CreateUserProfileView(generics.ListCreateAPIView):

    serializer_class = CreateUserProfileSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination
    queryset = UserProfile.objects.all().order_by('user')

class UpdateUserProfileView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination
    serializer_class = UpdateUserProfileSerializer
    queryset = UserProfile.objects.all()

    def get_object(self):

        try:
            user_profile = UserProfile.objects.get(user=self.request.user)

        except UserProfile.DoesNotExist:
            return Response("User Profile does not exist", status=status.HTTP_400_BAD_REQUEST)

        return user_profile

class UserForgotPasswordView(APIView):
    @swagger_auto_schema(
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=["email"],
                properties={
                    "email": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="The mail is sent to reset password",
                    )
                },
            ),
            responses={
                200: "email send successfully",
                400: "Bad Request: email is required",
                500: "Internal Server Error",
            },
        )
    def post(self, request):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = f'http://localhost:8000/api/auth/resetpassword/{uid}/{token}'
            html_content = render_to_string(
                "forgot_password_email.html", {"reset_url": reset_url}
            )
            from_mail = AZURE_SENDER_ADDRESS
            subject = 'Password Reset Request'

            send_azure_mail(subject, html_content, from_mail, email)

            # email_message = EmailMessage(subject, html_content,from_mail,[email])

            # email_message.content_subtype = "html"  # Indicate that the email content is HTML
            # email_message.send()

            return Response(
                {"message": "Password reset email sent", 'reset_url':f'{reset_url}'}, status=status.HTTP_200_OK
            )

        except ObjectDoesNotExist:
            return Response(
                {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

class ResetPasswordView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["password", "confirm_password"],
            properties={
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="password"
                ),
                "confirm_password": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="confirm_password",
                ),
            },
        ),
            responses={
                200: "email send successfully",
                400: "Bad Request: email is required",
                500: "Internal Server Error",
            },
        )
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                new_password = request.data.get("password")
                confirm_password = request.data.get('confirm_password')

                if new_password != confirm_password:
                    return Response(
                        {"message": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST
                    )

                user.set_password(new_password)
                user.save()
                return Response(
                    {"message": "Password reset successful"}, status=status.HTTP_200_OK
                )
            return Response(
                {"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
            return Response(
                {"message": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST
            )