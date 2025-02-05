from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator


def send_verification_email(user, request):
    """
    Sends an email to verify your email.
    """
    token = default_token_generator.make_token(user)
    verification_link = f"{request.scheme}://{request.get_host()}/auth/verify-email/{token}/"

    subject = "Email Verification"
    message = f"""
    Hi {user.email},
    Please verify your email by clicking the link below:
    {verification_link}
    """

    send_mail(
        subject,
        message,
        "your_email@gmail.com",
        [user.email],
        fail_silently=False,
    )


def send_reset_password_email(user, request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_password_link = f"{request.scheme}://{request.get_host()}/auth/password-reset-confirm/{uid}/{token}/"
    subject = "Rest Password"
    message = f"""
    Hi {user.email},
    Click the link below to reset your password:
    {reset_password_link}
    If you did not request this, please ignore this email.
    """

    send_mail(
        subject,
        message,
        "your_email@gmail.com",
        [user.email],
        fail_silently=False,
    )

