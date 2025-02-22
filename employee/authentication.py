import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from employee.models import User, BlacklistedToken

# JWT settings from Django settings
JWT_SETTINGS = settings.JWT_SETTINGS
JWT_SECRET = JWT_SETTINGS['SECRET_KEY']
JWT_ALGORITHM = JWT_SETTINGS['ALGORITHM']

class JWTAuthentication(BaseAuthentication):
    """
    Custom JWT authentication class.
    Extracts and validates JWT tokens from the request.
    """

    def authenticate(self, request):
        """
        Authenticate the user using the JWT token.
        """
        # Extract the token from the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None  # No token provided

        # Check if the header is in the correct format: "Bearer <token>"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed('Invalid token header. Use "Bearer <token>".')

        token = parts[1]

        try:
            # Decode the token
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

            # Check if the token is blacklisted
            if BlacklistedToken.objects.filter(token=token).exists():
                raise AuthenticationFailed('Token has been blacklisted. Please log in again.')

            # Fetch the user from the database
            user_id = payload.get(JWT_SETTINGS['USER_ID_CLAIM'])
            if not user_id:
                raise AuthenticationFailed('Invalid token: User ID not found.')

            user = User.objects.get(id=user_id)

            # Return the authenticated user and token
            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired. Please log in again.')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token.')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')

def validate_token(token, token_type='access'):
    """
    Validate a JWT token and return its payload.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Check if the token type matches
        if payload.get(JWT_SETTINGS['TOKEN_TYPE_CLAIM']) != token_type:
            raise AuthenticationFailed('Invalid token type.')

        # Check if the token is blacklisted
        if BlacklistedToken.objects.filter(token=token).exists():
            raise AuthenticationFailed('Token has been blacklisted.')

        return payload

    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token has expired.')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid token.')

class TokenError(Exception):
    """
    Custom exception for token-related errors.
    """
    pass


