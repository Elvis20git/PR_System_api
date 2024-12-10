from django.contrib import admin
from django.urls import path, include
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from PR_api.views import (
    CreateUserView,
    LoginUserView,
    UserProfileView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    UserLastNameView,
    HODUserView
)

@ensure_csrf_cookie
def csrf(request):
    return JsonResponse({'csrfToken': 'success'})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/', CreateUserView.as_view(), name='register'),
    path('api/login/', LoginUserView.as_view(), name='login'),
    path('api/users/', UserLastNameView.as_view(), name='user-lastname-list'),
    path('api/hod-users/', HODUserView.as_view(), name='hod-users-list'),
    path('api/profile/', UserProfileView.as_view(), name='profile'),
    path('api/password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('api/password-reset-confirm/<str:uidb64>/<str:token>/',
         PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/csrf/', csrf, name='csrf'),  # Added CSRF endpoint
    path("api-auth/", include("rest_framework.urls")),
    path("api/", include("PR_api.urls")),
]