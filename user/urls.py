from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

from user.views import CreateUserView, ManageUserView, GoogleView, VerifyEmailView

app_name = "user"

urlpatterns = [
    # Default django user
    path("registration/", CreateUserView.as_view(), name="create"),
    path("me/", ManageUserView.as_view(), name="manage"),
    # JWT TOKEN
    path("sign-in/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    # GOOGLE TOKEN
    path("google/", GoogleView.as_view(), name="google_auth"),

    path("verify-email/<str:uidb64>/<str:token>/", VerifyEmailView.as_view(), name="verify_email"),

]
