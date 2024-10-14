# Generated by Django 5.1 on 2024-10-09 14:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0003_usersignup_is_super'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersignup',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='usersignup',
            name='verification_code',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
