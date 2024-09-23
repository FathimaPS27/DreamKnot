from django.db import models
from django_countries.fields import CountryField
from django.utils import timezone

class UserSignup(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    country = CountryField() 
    state = models.CharField(max_length=100)  
    place = models.CharField(max_length=100)  
    phone = models.CharField(max_length=15)
    role = models.CharField(max_length=10, choices=[('vendor', 'Vendor'), ('user', 'User')])  
    reset_token = models.CharField(max_length=100, blank=True, null=True)
    reset_token_created_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(UserSignup, on_delete=models.CASCADE)
    wedding_date = models.DateField(null=True, blank=True)
    event_held = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.user.name

class VendorProfile(models.Model):
    user = models.OneToOneField(UserSignup, on_delete=models.CASCADE)
    business_category = models.CharField(max_length=255, blank=True)
    company_name = models.CharField(max_length=255, blank=True)
    bio = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.company_name if self.company_name else self.user.name

class WeddingTask(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    description = models.TextField()
    is_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.description
