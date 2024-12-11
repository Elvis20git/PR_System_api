from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    is_HOD = models.BooleanField(default=False)
    department = models.CharField(max_length=50, blank=True, null=True)

class PurchaseRequest(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'PENDING'),
        ('APPROVED', 'APPROVED'),
        ('REJECTED', 'REJECTED'),
    ]

    DEPARTMENT_CHOICES = [
        ('IT & Business Support', 'IT & Business Support'),
        ('Finance', 'Finance'),
        ('Quality Assurance', 'Quality Assurance'),
    ]

    PURCHASE_TYPE_CHOICES = [
        ('Raw Material', 'Raw Material'),
        ('Spare parts', 'Spare parts'),
        ('Consumables', 'Consumables'),
        ('Indirect Goods', 'Indirect Goods'),
        ('Services', 'Services'),
        ('CAPEX/ Small Projects', 'CAPEX/ Small Projects'),
    ]

    title = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES)
    initiator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchase_requests')
    approver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='approved_requests')
    purchase_type = models.CharField(max_length=50, choices=PURCHASE_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    rejection_reason = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'purchase_request'

    def __str__(self):
        return f"{self.title} - {self.status}"


class PurchaseRequestItem(models.Model):
    purchase_request = models.ForeignKey(PurchaseRequest, on_delete=models.CASCADE, related_name='items')
    item_title = models.CharField(max_length=255)
    item_quantity = models.IntegerField()
    item_code = models.CharField(max_length=50, null=True, blank=True, default='N/A')
    unit_of_measurement = models.CharField(max_length=50, null=True, blank=True, default='N/A')
    description = models.TextField()

    class Meta:
        db_table = 'purchase_request_item'

    def __str__(self):
        return f"{self.item_title} - {self.purchase_request.title}"

class Notification(models.Model):
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    purchase_request_id = models.IntegerField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']




























# class PurchaseRequest(models.Model):
#     STATUS_CHOICES = [
#         ('PENDING', 'PENDING'),
#         ('APPROVED', 'APPROVED'),
#         ('REJECTED', 'REJECTED'),
#     ]
#     DEPARTMENT_CHOICES = [
#         ('IT & Business Support', 'IT & Business Support'),
#         ('Finance', 'Finance'),
#         ('Quality Assurance', 'Quality Assurance'),
#     ]
#
#     PURCHASE_TYPE_CHOICES = [
#         ('Raw Material', 'Raw Material'),
#         ('Spareparts', 'Spareparts'),
#         ('Consumables', 'Consumables'),
#         ('Indirect Goods', 'Indirect Goods'),
#         ('Services', 'Services'),
#         ('CAPEX/ Small Projects', 'CAPEX/ Small Projects'),
#     ]
#
#     @staticmethod
#     def get_initiator_choices():
#         User = get_user_model()
#         return [(user.id, str(user)) for user in User.objects.all()]
#
#     @staticmethod
#     def get_approver_choices():
#         User = get_user_model()
#         return [(user.id, str(user)) for user in User.objects.filter(is_HOD=True)]
#
#     title = models.CharField(max_length=100)
#     department = models.CharField(max_length=100, choices=DEPARTMENT_CHOICES)
#     status = models.CharField(max_length=100, choices=STATUS_CHOICES)
#     initiator = models.ForeignKey(
#         get_user_model(),
#         on_delete=models.CASCADE,
#         related_name='purchase_requests'
#     )
#     approver = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='approver')
#     purchase_type = models.CharField(max_length=100, choices=PURCHASE_TYPE_CHOICES)
#     created_at = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return self.title
#
# class PurchaseRequestItem(models.Model):
#     purchase_request = models.ForeignKey(PurchaseRequest, on_delete=models.CASCADE, related_name='items')
#     item_title = models.CharField(max_length=100)
#     item_quantity = models.PositiveIntegerField()
#     item_code = models.CharField(max_length=50, blank=True, null=True)
#     unit_of_measurement = models.CharField(max_length=50, blank=True, null=True)
#     description = models.CharField(max_length=100)
#
#     def __str__(self):
#         return f"{self.item_title} - {self.purchase_request.title}"


