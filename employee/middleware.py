import jwt
from django.conf import settings
from employee.models import User
from employee.authentication import validate_token, TokenError

class JWTAuthenticationMiddleware:
    """Middleware for JWT authentication"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = self.get_token_from_header(request)
        
        if token:
            try:
                payload = validate_token(token, 'access')
                user = User.objects.get(id=payload[settings.JWT_SETTINGS['USER_ID_CLAIM']])
                request.user = user
            except (TokenError, User.DoesNotExist):
                pass

        response = self.get_response(request)
        return response

    def get_token_from_header(self, request):
        """Extract token from the Authorization header"""
        auth_header = request.headers.get(settings.JWT_SETTINGS['AUTH_HEADER_NAME'].replace('HTTP_', ''))
        if not auth_header:
            return None
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0] not in settings.JWT_SETTINGS['AUTH_HEADER_TYPES']:
            return None
            
        return parts[1]

