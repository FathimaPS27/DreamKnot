# Generated by Django 5.1 on 2024-11-10 09:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0013_booking_razorpay_order_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='refund_amount',
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True),
        ),
    ]
