# Generated by Django 5.0.9 on 2024-12-10 12:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('PR_api', '0005_notification'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='department',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
