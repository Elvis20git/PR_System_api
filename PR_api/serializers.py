from rest_framework import serializers
from .models import PurchaseRequest, PurchaseRequestItem, User, Notification
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse

from PR_Backend.settings import EMAIL_HOST_USER


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'department', 'password', 'is_HOD']
        extra_kwargs = {"password": {"write_only": True}}
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


User = get_user_model()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Check if email exists in the system
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address")
        return value

    def create(self, validated_data):
        # Find the user
        user = User.objects.get(email=validated_data['email'])

        # Generate a password reset token
        token = default_token_generator.make_token(user)

        # Change this part - construct frontend URL instead of API URL
        frontend_url = "http://192.168.222.43:5173"  # Your React frontend URL
        reset_url = f"{frontend_url}/reset-password/{user.pk}/{token}"

        # Send email
        send_mail(
            subject= 'Password Reset Request',
            message= f'Please click the following link to reset your password: {reset_url}',
            from_email= EMAIL_HOST_USER,
            recipient_list= [user.email],
            fail_silently=False,
        )

        return validated_data


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Validate passwords match
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        try:
            # Verify user and token
            user = User.objects.get(pk=data['uid'])
            if not default_token_generator.check_token(user, data['token']):
                raise serializers.ValidationError("Invalid or expired token")
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid user")

        return data

    def create(self, validated_data):
        user = User.objects.get(pk=validated_data['uid'])
        user.set_password(validated_data['new_password'])
        user.save()
        return user


class PurchaseRequestItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchaseRequestItem
        fields = ['id', 'item_title', 'item_quantity', 'item_code',
                 'unit_of_measurement', 'description']


class PurchaseRequestSerializer(serializers.ModelSerializer):
    items = PurchaseRequestItemSerializer(many=True)
    initiator = serializers.PrimaryKeyRelatedField(read_only=True)
    approver = serializers.PrimaryKeyRelatedField(read_only=True)  # Make approver read-only

    class Meta:
        model = PurchaseRequest
        fields = ['id', 'title', 'status', 'department', 'initiator',
                  'approver', 'purchase_type', 'items', 'rejection_reason']
        read_only_fields = ['id', 'initiator', 'approver']  # Explicitly set read-only fields

    def validate(self, data):
        # Validate status changes
        if self.instance and 'status' in data:
            if self.instance.status != 'PENDING' and data['status'] != self.instance.status:
                raise serializers.ValidationError({
                    "status": "Can only update status of PENDING purchase requests."
                })

            if data['status'] == 'REJECTED' and not data.get('rejection_reason'):
                raise serializers.ValidationError({
                    "rejection_reason": "Rejection reason is required when rejecting a purchase request."
                })

        return data

    def create(self, validated_data):
        items_data = validated_data.pop('items')
        purchase_request = PurchaseRequest.objects.create(**validated_data)

        for item_data in items_data:
            PurchaseRequestItem.objects.create(purchase_request=purchase_request, **item_data)

        return purchase_request

    def update(self, instance, validated_data):
        items_data = validated_data.pop('items', [])

        # Update purchase request fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Handle items
        instance.items.all().delete()  # Remove existing items
        for item_data in items_data:
            PurchaseRequestItem.objects.create(purchase_request=instance, **item_data)

        return instance


class DashboardMetricsSerializer(serializers.Serializer):
    total_requests = serializers.IntegerField()
    pending_approval = serializers.IntegerField()
    approved_this_month = serializers.IntegerField()
    rejected_this_month = serializers.IntegerField()
    total_budget_used = serializers.DecimalField(max_digits=10, decimal_places=2)
    budget_limit_percentage = serializers.FloatField()

    # For the trends chart
    monthly_trends = serializers.ListField(child=serializers.DictField())

    # For the department distribution pie chart
    department_distribution = serializers.ListField(child=serializers.DictField())

    # For top request categories
    top_categories = serializers.ListField(child=serializers.DictField())

    # For recent activity
    recent_activity = serializers.ListField(child=serializers.DictField())


class RequestTrendSerializer(serializers.Serializer):
    month = serializers.DateTimeField()
    approved = serializers.IntegerField()
    pending = serializers.IntegerField()
    rejected = serializers.IntegerField()

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_HOD']
        read_only_fields = ['id', 'username', 'email']  # These fields can't be changed via profile update



class UserLastNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'last_name']



class HODUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'last_name']


class PurchaseRequestListSerializer(serializers.ModelSerializer):
    initiator_name = serializers.CharField(source='initiator.first_name', read_only=True)
    # approver_name = serializers.CharField(source='approver.username', read_only=True)

    class Meta:
        model = PurchaseRequest
        fields = [
            'id',
            'title',
            'department',
            'purchase_type',
            'status',
            'created_at',
            'initiator_name',
        ]

class PurchaseRequestStatusUpdateSerializer(serializers.ModelSerializer):
    rejection_reason = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = PurchaseRequest
        fields = ['status', 'rejection_reason']

    def validate(self, data):
        if data.get('status') == 'REJECTED' and not data.get('rejection_reason'):
            raise serializers.ValidationError({
                "rejection_reason": "Rejection reason is required when rejecting a purchase request."
            })
        return data

    def update(self, instance, validated_data):
        instance.status = validated_data.get('status', instance.status)
        instance.rejection_reason = validated_data.get('rejection_reason', instance.rejection_reason)
        instance.save()
        return instance


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'message', 'purchase_request_id', 'is_read', 'created_at']

