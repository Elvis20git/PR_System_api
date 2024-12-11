from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import authenticate, get_user_model
from django.db.models.functions.datetime import TruncMonth
from django.shortcuts import render, get_object_or_404
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from PR_api.models import User, Notification
from rest_framework import generics, status, viewsets
from .serializers import UserSerializer, PurchaseRequestSerializer, PurchaseRequestItemSerializer, \
    UserProfileSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, UserLastNameSerializer, \
    HODUserSerializer, PurchaseRequestListSerializer, NotificationSerializer, DashboardMetricsSerializer, \
    RequestTrendSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import PurchaseRequest, PurchaseRequestItem
from django.db.models import Q, Count, Sum
from django.utils import timezone
from rest_framework.viewsets import ViewSet
from datetime import datetime, timedelta

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class LoginUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'is_HOD': user.is_HOD,  # Assuming you have this field
            })
        else:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "Password reset email has been sent."},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token):
        data = {
            'uid': uidb64,
            'token': token,
            'new_password': request.data.get('new_password'),
            'confirm_password': request.data.get('confirm_password')
        }

        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"detail": "Password has been reset successfully."},
            status=status.HTTP_200_OK
        )


class PurchaseRequestViewSet(viewsets.ModelViewSet):
    queryset = PurchaseRequest.objects.all()
    serializer_class = PurchaseRequestSerializer
    permission_classes = [AllowAny]

    def get_department_head(self, department):
        User = get_user_model()
        try:
            # Assuming you have a field in your User model to identify HODs
            # and their associated department
            hod = User.objects.get(is_HOD=True, department=department)
            return hod
        except User.DoesNotExist:
            return None

    def perform_create(self, serializer):
        # Save the purchase request
        purchase_request = serializer.save(initiator=self.request.user)

        # Get the HOD for the initiator's department
        hod = self.get_department_head(self.request.user.department)

        # Send notification if HOD exists
        if hod:
            send_notification(
                hod.id,
                f"New purchase request #{purchase_request.id} requires your approval",
                purchase_request.id
            )

    def list(self, request):
        queryset = self.get_queryset()
        serializer = PurchaseRequestSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        instance = get_object_or_404(PurchaseRequest, pk=pk)

        # Validate the request status
        if instance.status != 'PENDING' and 'status' in request.data:
            return Response(
                {"detail": "Can only update status of PENDING purchase requests."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if rejection reason is provided when rejecting
        if request.data.get('status') == 'REJECTED' and not request.data.get('rejection_reason'):
            return Response(
                {"detail": "Rejection reason is required when rejecting a purchase request."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(instance, data=request.data)

        if serializer.is_valid():
            # If status is changing to APPROVED or REJECTED, set approver
            if 'status' in request.data:
                new_status = request.data['status']
                if new_status in ['APPROVED', 'REJECTED']:
                    # Save with approver
                    updated_request = serializer.save(approver=request.user)

                    # Send notification to the initiator about the status change
                    send_notification(
                        updated_request.initiator.id,
                        f"Your purchase request #{updated_request.id} has been {new_status.lower()}",
                        updated_request.id
                    )
                else:
                    serializer.save()
            else:
                serializer.save()

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        return self.update(request, pk)

    def destroy(self, request, pk=None):
        instance = get_object_or_404(PurchaseRequest, pk=pk)

        if instance.status != 'PENDING':
            return Response(
                {"detail": "Cannot delete purchase request that is not in PENDING status."},
                status=status.HTTP_400_BAD_REQUEST
            )

        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Count, Sum, Q
from django.db.models.functions import TruncWeek, TruncMonth, TruncYear
from datetime import datetime, timedelta

class DashboardViewSet(ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['GET'])
    def metrics(self, request):
        # Get date range and period filters from query params
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        period = request.query_params.get('period', 'Monthly')

        # Base queryset with date filtering
        base_queryset = PurchaseRequest.objects.all()
        if start_date:
            base_queryset = base_queryset.filter(created_at__gte=start_date)
        if end_date:
            base_queryset = base_queryset.filter(created_at__lte=end_date)

        # Calculate key metrics
        total_requests = base_queryset.count()
        pending_approval = base_queryset.filter(status='PENDING').count()

        # Calculate month-over-month metrics
        current_month = timezone.now().month
        current_year = timezone.now().year

        approved_this_month = base_queryset.filter(
            status='APPROVED',
            created_at__month=current_month,
            created_at__year=current_year
        ).count()

        rejected_this_month = base_queryset.filter(
            status='REJECTED',
            created_at__month=current_month,
            created_at__year=current_year
        ).count()

        # Calculate trends based on selected period
        trunc_func = {
            'Weekly': TruncWeek,
            'Monthly': TruncMonth,
            'Yearly': TruncYear
        }.get(period, TruncMonth)

        # Get default date range based on period
        now = timezone.now()
        if period == 'Weekly':
            default_start = now - timedelta(weeks=12)  # Last 12 weeks
        elif period == 'Monthly':
            default_start = now - timedelta(days=365)  # Last 12 months
        else:  # Yearly
            default_start = now - timedelta(days=365*3)  # Last 3 years

        if not start_date:
            base_queryset = base_queryset.filter(created_at__gte=default_start)

        trends = (
            base_queryset
            .annotate(period_date=trunc_func('created_at'))
            .values('period_date')
            .annotate(
                approved=Count('id', filter=Q(status='APPROVED')),
                pending=Count('id', filter=Q(status='PENDING')),
                rejected=Count('id', filter=Q(status='REJECTED'))
            )
            .order_by('period_date')
        )

        # Transform the trends data for better frontend consumption
        formatted_trends = [
            {
                'month': item['period_date'].isoformat(),
                'approved': item['approved'],
                'pending': item['pending'],
                'rejected': item['rejected']
            }
            for item in trends
        ]

        # Calculate department distribution
        department_distribution = (
            base_queryset
            .values('department')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Get recent activity
        recent_activity = (
            base_queryset
            .select_related('initiator')
            .order_by('-created_at')[:5]
            .values('id', 'title', 'status', 'department', 'created_at')
        )

        # Get top request categories
        top_categories = (
            base_queryset
            .values('purchase_type')
            .annotate(
                count=Count('id'),
                total_amount=Sum('items__item_quantity')
            )
            .order_by('-count')[:5]
        )

        # Prepare response data
        dashboard_data = {
            'total_requests': total_requests,
            'pending_approval': pending_approval,
            'approved_this_month': approved_this_month,
            'rejected_this_month': rejected_this_month,
            'total_budget_used': 847000,
            'budget_limit_percentage': 75,
            'monthly_trends': formatted_trends,
            'department_distribution': department_distribution,
            'top_categories': top_categories,
            'recent_activity': recent_activity
        }

        serializer = DashboardMetricsSerializer(dashboard_data)
        return Response(serializer.data)


class PurchaseRequestStatusViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @action(detail=True, methods=['patch'])
    def update_status(self, request, pk=None):
        """
        Updates only the status of a purchase request.
        Requires status in request data and rejection_reason if status is REJECTED.
        """
        purchase_request = get_object_or_404(PurchaseRequest, pk=pk)
        new_status = request.data.get('status')
        rejection_reason = request.data.get('rejection_reason')

        # Validate the new status is one of the valid choices
        if new_status not in dict(PurchaseRequest.STATUS_CHOICES):
            return Response(
                {"detail": "Invalid status provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the purchase request is already processed
        if purchase_request.status != 'PENDING':
            return Response(
                {"detail": "Can only update status of PENDING purchase requests."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate rejection reason is provided when rejecting
        if new_status == 'REJECTED' and not rejection_reason:
            return Response(
                {"detail": "Rejection reason is required when rejecting a purchase request."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update the purchase request
        purchase_request.status = new_status
        if new_status == 'REJECTED':
            purchase_request.rejection_reason = rejection_reason

        if new_status in ['APPROVED', 'REJECTED']:
            purchase_request.approver = request.user

        purchase_request.save()

        # Send notification to the initiator
        send_notification(
            purchase_request.initiator.id,
            f"Your purchase request #{purchase_request.id} has been {new_status.lower()}",
            purchase_request.id
        )

        # Serialize and return the updated purchase request
        serializer = PurchaseRequestSerializer(purchase_request)
        return Response(serializer.data)


class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.filter(recipient=self.request.user)

    def mark_as_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response(status=204)


def send_notification(user_id, message, pr_id):
    notification = Notification.objects.create(
        recipient_id=user_id,
        message=message,
        purchase_request_id=pr_id
    )

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{user_id}",
        {
            "type": "notify",
            "data": {
                "id": notification.id,
                "message": message,
                "purchase_request_id": pr_id,
                "created_at": notification.created_at.isoformat()
            }
        }
    )


class UserLastNameView(generics.ListAPIView):
    queryset = get_user_model().objects.all().order_by('last_name')  # Sort alphabetically
    serializer_class = UserLastNameSerializer
    permission_classes = [AllowAny]

class HODUserView(generics.ListAPIView):
    serializer_class = HODUserSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return get_user_model().objects.filter(is_HOD=True).order_by('last_name')


class PurchaseRequestListView(generics.ListAPIView):
    serializer_class = PurchaseRequestListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return PurchaseRequest.objects.filter(approver=self.request.user)
        return PurchaseRequest.objects.none()  # Return empty queryset if user is not authenticated

    def list(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        return super().list(request, *args, **kwargs)





# Create your views here.
