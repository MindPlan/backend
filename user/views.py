import requests


from django.contrib.auth.tokens import default_token_generator
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.core.files.base import ContentFile
from django.utils.text import slugify
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from user.models import User
from user.permissions import IsEmailVerified
from user.serializers import UserSerializer
from user.utils import send_verification_email


class CreateUserView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)
    def perform_create(self, serializer):
        user = serializer.save()
        send_verification_email(user, self.request)
        return Response({"message": "User created successfully. Please verify your email."})


class ManageUserView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, IsEmailVerified)

    def get_object(self):
        return self.request.user


class GoogleView(APIView):
    """
    Endpoint for Google ID token verification
    """
    permission_classes = (AllowAny,)
    def post(self, request):
        token = request.data.get("credential")
        client_id = request.data.get("clientId")
        if not token or not client_id:
            return Response({"message": "Token and clientId are required."}, status=HTTP_400_BAD_REQUEST)

        try:
            # Google ID token verification
            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                client_id
            )

            # Checking if the token was issued by Google
            if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
                return Response({"message": "Invalid token issuer."}, status=HTTP_400_BAD_REQUEST)

        except ValueError as e:
            return Response({"message": f"Invalid or expired token: {str(e)}"}, status=HTTP_400_BAD_REQUEST)

        # Getting data from the token
        email = idinfo.get("email")
        first_name = idinfo["given_name"]
        last_name = idinfo.get("family_name")
        img_url = idinfo.get("picture")

        if not email:
            return Response({"message": "Email is required."}, status=HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            # Create or get a user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": first_name or "",
                    "last_name": last_name or "",
                },
            )

            if not created:
                # Updating an existing user, but only if new data is provided
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name

            if img_url:
                response = requests.get(img_url)
                if response.status_code == 200:
                    user.image.save(
                        f"{slugify(user.email)}-google-photo.jpg",
                        ContentFile(response.content),
                        save=False
                    )

            # Automatically verify email for Google accounts
            user.is_email_verified = True
            user.save()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        response = {
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "image": user.image.url if user.image else None,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
        }
        return Response(response)


class VerifyEmailView(APIView):

    permission_classes = (AllowAny,)

    def get(self, request, token):
        try:
            # Find user by checking token validity for all users
            user = None
            for candidate_user in User.objects.all():
                if default_token_generator.check_token(candidate_user, token):
                    user = candidate_user
                    break

            if user is None:
                return Response({"message": "Invalid or expired token."}, status=400)

            # Mark email as verified
            user.is_email_verified = True
            user.save()
            return Response({"message": "Email successfully verified."})
        except Exception as e:
            return Response({"message": "Invalid link."}, status=400)


class ResendVerificationEmailView(APIView):

    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"message": "Email is required."}, status=400)

        try:
            user = get_object_or_404(User, email=email)
            if user.is_email_verified:
                return Response({"message": "Email is already verified."}, status=400)

            send_verification_email(user, request)
            return Response({"message": "Verification email resent."})
        except Exception as e:
            return Response({"message": "Unable to resend email. Please try again later."}, status=400)
