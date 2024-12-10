from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PurchaseRequestViewSet, PurchaseRequestListView

router = DefaultRouter()
router.register(r'purchase-requests', PurchaseRequestViewSet, basename='purchaseRequests')

urlpatterns = [
    path('', include(router.urls)),
    path('purchase-requests-list/', PurchaseRequestListView.as_view(), name='purchase-request-list'),
]