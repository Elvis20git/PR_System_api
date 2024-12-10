from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import PurchaseRequest, PurchaseRequestItem

admin.site.register(PurchaseRequest)
admin.site.register(PurchaseRequestItem)