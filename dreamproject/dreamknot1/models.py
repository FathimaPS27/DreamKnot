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
    
    

TASK_MONTH_CHOICES = [
    ('6-12', '6-12 Months Before'),
    ('4-6', '4-6 Months Before'),
    ('2-4', '2-4 Months Before'),
    ('1-2', '1-2 Months Before'),
    ('1-2 Weeks', '1-2 Weeks Before'),
    ('Final Days', 'Final Days'),
    ('Wedding Day', 'Wedding Day'),
]

class WeddingTask(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    description = models.CharField(max_length=255)
    task_month = models.CharField(max_length=20, choices=TASK_MONTH_CHOICES, default='6-12')
    is_completed = models.BooleanField(default=False)
    is_predefined = models.BooleanField(default=False)  # To differentiate predefined vs custom tasks
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)  # Auto-updates on every save

    def __str__(self):
        return self.description
    


class RSVPInvitation(models.Model):
    couple = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    guest_name = models.CharField(max_length=255)
    guest_email = models.EmailField()
    wedding_date = models.DateField()
    venue = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    time = models.TimeField()
    is_accepted = models.BooleanField(null=True, blank=True)  # Will be True for attending, False for not attending, None if no response yet
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.guest_name} - RSVP for {self.couple.name}"


class Service(models.Model):
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='services')
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=255)
    availability = models.BooleanField(default=True)
    status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

# Service Image Model
class ServiceImage(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='service_images/')
    status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.service.name}"

# Rating Model
class Rating(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='ratings')
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    rating = models.IntegerField()
    status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('service', 'user')

    def __str__(self):
        return f"{self.user.username} rated {self.service.name} {self.rating}/5"

# Booking Model
class Booking(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    booking_date = models.DateTimeField(default=timezone.now)
    event_date = models.DateField()
    event_address = models.CharField(max_length=255, blank=True, null=True)  # Optional event address

    status = models.IntegerField(default=0, choices=[(0, 'Pending'), (1, 'Confirmed'), (2, 'Completed'), (3, 'Canceled')])

    def __str__(self):
        return f"{self.user.username} booked {self.service.name} on {self.event_date}"

# Favorite Model
class Favorite(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'service')

    def __str__(self):
        return f"{self.user.username} favorited {self.service.name}"

class VendorImage(models.Model):
    vendor_profile = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='vendor_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=True)  # Status field (0 for inactive, 1 for active)

    def __str__(self):
        return f"Image for {self.vendor_profile.company_name or self.vendor_profile.user.name}"