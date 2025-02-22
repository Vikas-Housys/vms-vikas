import jwt
from django.conf import settings
from datetime import datetime, timezone
from employee.models import BlacklistedToken

JWT_SETTINGS = settings.JWT_SETTINGS
JWT_SECRET = JWT_SETTINGS['SECRET_KEY']
JWT_ALGORITHM = JWT_SETTINGS['ALGORITHM']

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

def generate_tokens(user):
    try:
        current_time = datetime.now(timezone.utc)
        
        # Access token payload
        access_token_payload = {
            JWT_SETTINGS['USER_ID_CLAIM']: getattr(user, JWT_SETTINGS['USER_ID_FIELD']),
            'exp': current_time + JWT_SETTINGS['ACCESS_TOKEN_LIFETIME'],
            'iat': current_time,
            JWT_SETTINGS['TOKEN_TYPE_CLAIM']: 'access',
        }
        
        # Refresh token payload
        refresh_token_payload = {
            JWT_SETTINGS['USER_ID_CLAIM']: getattr(user, JWT_SETTINGS['USER_ID_FIELD']),
            'exp': current_time + JWT_SETTINGS['REFRESH_TOKEN_LIFETIME'],
            'iat': current_time,
            JWT_SETTINGS['TOKEN_TYPE_CLAIM']: 'refresh',
        }
        
        # Encode tokens
        access_token = jwt.encode(access_token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        refresh_token = jwt.encode(refresh_token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return {
            'access': access_token,
            'refresh': refresh_token
        }
    except Exception as e:
        raise TokenError('Failed to generate tokens.')

def validate_token(token, token_type='access'):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload[JWT_SETTINGS['TOKEN_TYPE_CLAIM']] != token_type:
            raise TokenError('Invalid token type')
        if BlacklistedToken.objects.filter(token=token).exists():
            raise TokenError('Token is blacklisted')
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenError('Token has expired')
    except jwt.InvalidTokenError:
        raise TokenError('Invalid token')
    except Exception as e:
        raise TokenError('Failed to validate token')

def blacklist_token(token):
    try:
        payload = validate_token(token)
        user_id = payload[JWT_SETTINGS['USER_ID_CLAIM']]
        BlacklistedToken.objects.create(user_id=user_id, token=token)
        return True
    except TokenError as e:
        return False


