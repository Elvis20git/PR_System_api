from rest_framework import serializers
from PR_Backend.settings import EMAIL_HOST_USER
from PR_api.models import User
from . models import PurchaseRequest, PurchaseRequestItem
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'password', 'is_HOD']
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

        # Construct reset URL (you'll need to configure this in your urls.py)
        reset_url = self.context['request'].build_absolute_uri(
            reverse('password_reset_confirm', kwargs={'uidb64': user.pk, 'token': token})
        )

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

    class Meta:
        model = PurchaseRequest
        fields = ['id', 'title', 'status', 'department', 'initiator',
                 'approver', 'purchase_type', 'items', 'rejection_reason']

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