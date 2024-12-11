# App urls.py

from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter

from . import consumers
from .views import PurchaseRequestViewSet, PurchaseRequestListView, NotificationViewSet, PurchaseRequestStatusViewSet, \
    DashboardViewSet

router = DefaultRouter()
router.register(r'purchase-requests', PurchaseRequestViewSet, basename='purchaseRequests')
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'purchase-request-status', PurchaseRequestStatusViewSet, basename='purchase-request-status')
router.register(r'dashboard', DashboardViewSet, basename='dashboard')

urlpatterns = [
    path('', include(router.urls)),
    path('purchase-requests-list/', PurchaseRequestListView.as_view(), name='purchase-request-list'),
    path('notifications/', NotificationViewSet.as_view({'get': 'list'})),
    path('notifications/<int:pk>/mark-read/', NotificationViewSet.as_view({'post': 'mark_as_read'})),
]