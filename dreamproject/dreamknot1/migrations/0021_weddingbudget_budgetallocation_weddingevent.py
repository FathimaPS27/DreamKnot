# Generated by Django 5.1 on 2025-02-19 04:56

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0020_delete_vendorrecommendation'),
    ]

    operations = [
        migrations.CreateModel(
            name='WeddingBudget',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total_budget', models.DecimalField(decimal_places=2, max_digits=12)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('currency', models.CharField(default='INR', max_length=10)),
                ('wedding_type', models.CharField(choices=[('North_Indian', 'North Indian Wedding'), ('South_Indian', 'South Indian Wedding'), ('Bengali', 'Bengali Wedding'), ('Marathi', 'Marathi Wedding'), ('Muslim', 'Muslim Wedding'), ('Christian', 'Christian Wedding'), ('Destination', 'Destination Wedding')], max_length=50)),
                ('guest_count', models.PositiveIntegerField()),
                ('wedding_date', models.DateField()),
                ('location', models.CharField(max_length=100)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='dreamknot1.usersignup')),
            ],
        ),
        migrations.CreateModel(
            name='BudgetAllocation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category', models.CharField(choices=[('Venue', 'Venue'), ('Catering', 'Catering'), ('Decoration', 'Decoration'), ('Photography', 'Photography'), ('Attire', 'Attire'), ('Entertainment', 'Entertainment'), ('Mehendi', 'Mehendi'), ('Makeup', 'Makeup')], max_length=50)),
                ('allocated_amount', models.DecimalField(decimal_places=2, max_digits=12)),
                ('actual_spent', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('priority_level', models.IntegerField(choices=[(1, 'High'), (2, 'Medium'), (3, 'Low')])),
                ('cost_savings', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('notes', models.TextField(blank=True)),
                ('status', models.CharField(choices=[('planning', 'Planning'), ('in_progress', 'In Progress'), ('booked', 'Booked'), ('completed', 'Completed')], default='planning', max_length=20)),
                ('actual_vendors', models.ManyToManyField(blank=True, to='dreamknot1.service')),
                ('wedding_budget', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dreamknot1.weddingbudget')),
            ],
        ),
        migrations.CreateModel(
            name='WeddingEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_name', models.CharField(choices=[('Engagement', 'Engagement'), ('Haldi', 'Haldi'), ('Mehendi', 'Mehendi'), ('Sangeet', 'Sangeet'), ('Wedding', 'Wedding'), ('Reception', 'Reception')], max_length=50)),
                ('date', models.DateField()),
                ('budget', models.DecimalField(decimal_places=2, max_digits=12)),
                ('guest_count', models.PositiveIntegerField()),
                ('venue', models.CharField(blank=True, max_length=100)),
                ('wedding_budget', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dreamknot1.weddingbudget')),
            ],
        ),
    ]
