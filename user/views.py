from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
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

        if not email:
            return Response({"message": "Email is required."}, status=HTTP_400_BAD_REQUEST)

        # Create or get a user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": first_name or "",
                "last_name": last_name or "",
            },
        )

        if not created:
            # Updating an existing user
            user.first_name = first_name or user.first_name
            user.last_name = last_name or user.last_name
            user.save()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        response = {
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
        }
        return Response(response)


class VerifyEmailView(APIView):

    permission_classes = (AllowAny,)

    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_object_or_404(User, pk=uid)
        except (TypeError, ValueError, OverflowError):
            return Response({"message": "Invalid link."}, status=400)

        if default_token_generator.check_token(user, token):
            user.is_email_verified = True
            user.save()
            return Response({"message": "Email successfully verified."})
        return Response({"message": "Invalid or expired token."}, status=400)
