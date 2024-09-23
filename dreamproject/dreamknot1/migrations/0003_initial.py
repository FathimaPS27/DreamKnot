# Generated by Django 5.1 on 2024-08-30 08:38

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('dreamknot1', '0002_delete_cake_delete_location_delete_vendor'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=100)),
                ('event_location', models.CharField(max_length=100)),
                ('event_place', models.CharField(max_length=100)),
                ('event_date', models.DateField()),
                ('phone', models.CharField(max_length=15)),
                ('identity', models.CharField(choices=[('Bride', 'Bride'), ('Groom', 'Groom'), ('Other', 'Other')], max_length=10)),
            ],
        ),
    ]