from rest_framework.permissions import BasePermission


class IsEmailVerified(BasePermission):
    """
    Allows access only to users with a confirmed email.
    """
    message = "Your email is not verified."

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_email_verified
