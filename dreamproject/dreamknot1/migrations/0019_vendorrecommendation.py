# Generated by Django 5.1 on 2025-02-06 10:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dreamknot1', '0018_servicefeedback_sentimentanalysis_vendoranalytics'),
    ]

    operations = [
        migrations.CreateModel(
            name='VendorRecommendation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category', models.CharField(choices=[('service_quality', 'Service Quality'), ('communication', 'Communication'), ('value_for_money', 'Value for Money'), ('professionalism', 'Professionalism'), ('overall', 'Overall Experience')], max_length=50)),
                ('priority', models.CharField(choices=[('critical', 'Critical'), ('important', 'Important'), ('suggested', 'Suggested')], max_length=20)),
                ('score', models.FloatField()),
                ('suggestion', models.TextField()),
                ('supporting_feedback', models.JSONField()),
                ('is_addressed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('vendor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='recommendations', to='dreamknot1.vendorprofile')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
