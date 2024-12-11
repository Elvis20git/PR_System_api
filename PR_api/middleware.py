from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model


class TokenAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        # Get the token from query parameters
        query_string = scope.get('query_string', b'').decode()
        token = None
        if 'token=' in query_string:
            token = dict(param.split('=') for param in query_string.split('&')).get('token', None)

        scope['user'] = await self.get_user(token)
        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def get_user(self, token):
        if not token:
            return AnonymousUser()

        try:
            access_token = AccessToken(token)
            user = get_user_model().objects.get(id=access_token['user_id'])
            return user
        except Exception:
            return AnonymousUser()