# Generated by Django 5.1 on 2025-02-19 08:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0025_weddingevent_detailed_budget'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='weddingevent',
            name='detailed_budget',
        ),
    ]
