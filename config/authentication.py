import jwt
from django.conf import settings
from rest_framework import authentication
from rest_framework import exceptions
from users.models import User


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        try:
            # username = request.META.get("HTTP_X_USERNAME")
            token = request.META.get("HTTP_AUTHORIZATION")
            if token is None:
                return None
            bearer, jwt_token = token.split(" ")
            decoded = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=["HS256"])
            pk = decoded.get("pk")
            user = User.objects.get(pk=pk)
            return (user, None)
        except (ValueError, User.DoesNotExist):
            return None
        except jwt.exceptions.DecodeError:
            raise exceptions.AuthenticationFailed(detail="JWT Format Invalid")