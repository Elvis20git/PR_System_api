# Generated by Django 5.0.9 on 2024-12-09 12:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('PR_api', '0003_purchaserequest_updated_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='purchaserequest',
            name='rejection_reason',
            field=models.TextField(blank=True, null=True),
        ),
    ]
