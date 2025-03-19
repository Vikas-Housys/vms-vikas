from django.core.management.base import BaseCommand
from employee.models import User

class Command(BaseCommand):
    help = 'Cleanup expired refresh tokens from the database'

    def handle(self, *args, **kwargs):
        users = User.objects.exclude(refresh_token=None)
        for user in users:
            if not user.is_refresh_token_valid():
                user.clear_tokens()
                self.stdout.write(self.style.SUCCESS(f'Cleared expired refresh token for user {user.id}'))

