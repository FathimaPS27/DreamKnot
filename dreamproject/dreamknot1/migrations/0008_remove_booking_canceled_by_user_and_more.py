# Generated by Django 5.1 on 2024-10-13 15:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0007_booking_canceled_by_user_booking_cancellation_reason_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='booking',
            name='canceled_by_user',
        ),
        migrations.RemoveField(
            model_name='booking',
            name='cancellation_reason',
        ),
        migrations.RemoveField(
            model_name='booking',
            name='vendor_confirmed_at',
        ),
    ]