# Generated by Django 5.1 on 2024-10-09 10:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0002_booking_favorite_rating_rsvpinvitation_service_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersignup',
            name='is_super',
            field=models.BooleanField(default=False),
        ),
    ]
