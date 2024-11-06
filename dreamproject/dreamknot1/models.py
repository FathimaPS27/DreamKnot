from django.db import models
from django_countries.fields import CountryField
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.db.models import JSONField
from django_countries.fields import CountryField
from django.db import models

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
    is_verified = models.BooleanField(default=False)  # Field to check if email is verified
    verification_code = models.CharField(max_length=64, blank=True, null=True)  # Store verification code
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)
    
    # Field to indicate if the user is a superuser
    is_super = models.BooleanField(default=False)  # True if user is a superuser, False otherwise

    def __str__(self):
        return self.name

    # Custom method to check if the user is a superuser
    def is_superuser(self):
        return self.is_super


class UserProfile(models.Model):
    user = models.OneToOneField(UserSignup, on_delete=models.CASCADE)
    wedding_date = models.DateField(null=True, blank=True)
    event_held = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    up_status = models.BooleanField(default=True)

    def __str__(self):
        return self.user.name

class VendorProfile(models.Model):
    user = models.OneToOneField(UserSignup, on_delete=models.CASCADE)
    business_category = models.CharField(max_length=255, blank=True)
    company_name = models.CharField(max_length=255, blank=True)
    bio = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    vp_status = models.BooleanField(default=True)

    def __str__(self):
        return self.company_name if self.company_name else self.user.name
    
    
class WeddingTask(models.Model):
    TASK_MONTH_CHOICES = [
        ('6-12', '6-12 Months Before'),
        ('4-6', '4-6 Months Before'),
        ('2-4', '2-4 Months Before'),
        ('1-2', '1-2 Months Before'),
        ('1-2 Weeks', '1-2 Weeks Before'),
        ('Final Days', 'Final Days'),
        ('Wedding Day', 'Wedding Day'),
    ]


    user = models.ForeignKey('UserSignup', on_delete=models.CASCADE, null=True, blank=True)  # Link to UserSignup
    description = models.CharField(max_length=255)
    task_month = models.CharField(max_length=20, choices=TASK_MONTH_CHOICES, default='6-12')
    is_completed = models.BooleanField(default=False)
    is_predefined = models.BooleanField(default=False)  # True if predefined task
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    wt_status = models.BooleanField(default=True)

    def __str__(self):
        return self.description
    

class RSVPInvitation(models.Model):
    couple = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    couple_name = models.CharField(max_length=255)  # Couple's name
    event_name = models.CharField(max_length=255)   # Event name
    guest_name = models.CharField(max_length=255)
    guest_email = models.EmailField()
    event_date = models.DateField()               # Event date
    event_time = models.TimeField()                 # Event time
    event_description = models.TextField(blank=True, null=True)  # Optional event description
    venue = models.CharField(max_length=255)
    venue_address = models.CharField(max_length=255)  # Venue address
    phone_number = models.CharField(max_length=15)  # Contact number
    location_link = models.URLField(blank=True, null=True)  # Location link
    number_attending = models.PositiveIntegerField(null=True, blank=True)  # Allows guests to input number of attendees
    is_accepted = models.BooleanField(null=True, blank=True)  # Response status
    created_at = models.DateTimeField(auto_now_add=True)
    rsvp_status = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.guest_name} - RSVP for {self.couple.name}"


class Service(models.Model):
    CATEGORY_CHOICES = [
        ('Photography', 'Photography'),
        ('Catering', 'Catering'),
        ('Venue', 'Venue'),
        ('Decoration', 'Decoration'),
        ('MusicEntertainment', 'Music & Entertainment'),
        ('MakeupHair', 'Makeup & Hair'),
        ('Rentals', 'Rentals'),
        ('MehendiArtist', 'Mehendi Artist'),
    ]
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='services')
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=255, choices=CATEGORY_CHOICES)
    availability = models.BooleanField(default=True)
    status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    city = models.CharField(max_length=100, null=True, blank=True) # Adjust max_length as needed
    brochure = models.FileField(upload_to='brochures/', null=True, blank=True)
    # Main image for the service
    main_image = models.ImageField(upload_to='service_main_images/', null=True, blank=True)
    



    def __str__(self):
        return f"{self.name} - {self.category}"
    

# Service Image Model
class ServiceImage(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='service_images/')
    ing_status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.service.name}"


    


# Specialized service models with ForeignKey to Service

class VenueService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='venue_services')
    type_of_venue = models.CharField(max_length=50, choices=[('Indoor', 'Indoor'), ('Outdoor', 'Outdoor'), ('Destination', 'Destination')])
    location = models.CharField(max_length=255)
    capacity = models.PositiveIntegerField()
    pre_post_wedding_availability = models.BooleanField(default=True)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    day_rate = models.DecimalField(max_digits=10, decimal_places=2)
    setup_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
   

    def __str__(self):
        return f"Venue Service for {self.service.name}"


class CateringService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='catering_services')
    menu_planning = models.TextField()
    meal_service_type = models.CharField(max_length=50, choices=[('Buffet', 'Buffet'), ('Plated', 'Plated'), ('Food Stations', 'Food Stations')])
    dietary_options = models.TextField()
    price_per_person = models.DecimalField(max_digits=10, decimal_places=2)
    setup_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    minimum_guest_count = models.PositiveIntegerField(default=1)
   

    def __str__(self):
        return f"Catering Service for {self.service.name}"


class PhotographyService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='photography_services')
    package_duration = models.CharField(max_length=50, choices=[('Half-day', 'Half-day'), ('Full-day', 'Full-day')])
    styles = models.TextField()
    engagement_shoots = models.BooleanField(default=False)
    videography_options = models.BooleanField(default=False)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    

    def __str__(self):
        return f"Photography Service for {self.service.name}"


class MusicEntertainmentService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='music_entertainment_services')
    entertainment_options = models.TextField()
    sound_system_setup = models.BooleanField(default=False)
    multiple_entertainment_acts = models.BooleanField(default=False)
    emcee_services = models.BooleanField(default=False)
    playlist_customization = models.BooleanField(default=False)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
   

    def __str__(self):
        return f"Music Entertainment Service for {self.service.name}"


class MakeupHairService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='makeup_hair_services')
    grooming_services = models.TextField()
    trial_sessions = models.BooleanField(default=False)
    high_end_products = models.BooleanField(default=False)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
   

    def __str__(self):
        return f"Makeup & Hair Service for {self.service.name}"


class RentalsService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='rentals_services')
    rental_items = models.TextField()
    setup_services = models.BooleanField(default=False)
    rental_price_per_item = models.DecimalField(max_digits=10, decimal_places=2)
    deposit_required = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    duration_of_rental = models.CharField(max_length=50, choices=[('Hourly', 'Hourly'), ('Daily', 'Daily'), ('Weekly', 'Weekly')])
    

    def __str__(self):
        return f"Rentals Service for {self.service.name}"


class MehendiArtistService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='mehendi_artist_services')
    design_styles = models.TextField()
    duration_per_hand = models.DecimalField(max_digits=5, decimal_places=2)
    use_of_organic_henna = models.BooleanField(default=False)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
   

    def __str__(self):
        return f"Mehendi Artist Service for {self.service.name}"


class DecorationService(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='decoration_services')
    decor_themes = models.TextField()
    floral_arrangements = models.BooleanField(default=False)
    lighting_options = models.BooleanField(default=False)
    stage_decor = models.BooleanField(default=False)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
   

    def __str__(self):
        return f"Decoration Service for {self.service.name}"

# Rating Model
class Rating(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='ratings')
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    rating = models.IntegerField()
    rat_status = models.IntegerField(default=1, choices=[(0, 'Inactive'), (1, 'Active')])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('service', 'user')

    def __str__(self):
        return f"{self.user.name} rated {self.service.name} {self.rating}/5"

from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator
from decimal import Decimal

class Booking(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    booking_date = models.DateTimeField(default=timezone.now)
    event_name = models.CharField(max_length=255, null=True, blank=True)
    event_date = models.DateField()
    event_address = models.CharField(max_length=255, null=True, blank=True)
    user_address = models.CharField(max_length=255, null=True, blank=True)
    num_days = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    additional_requirements = models.TextField(blank=True, null=True)
    reference_images = models.ManyToManyField('ReferenceImage', blank=True)
    vendor_confirmed_at = models.DateTimeField(null=True, blank=True)
    canceled_by_user = models.BooleanField(default=False)
    cancellation_reason = models.TextField(blank=True, null=True)
    book_status = models.IntegerField(default=0, choices=[
        (0, 'Pending'),
        (1, 'Confirmed'),
        (2, 'Completed'),
        (3, 'Canceled')
    ])
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    booking_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # New fields for terms and conditions
    terms_and_conditions = models.TextField(blank=True, null=True)
    user_agreed_to_terms = models.BooleanField(default=False)
    user_agreement_date = models.DateTimeField(null=True, blank=True)

    razorpay_order_id = models.CharField(max_length=255, blank=True, null=True)  # Razorpay Order ID
    razorpay_payment_id = models.CharField(max_length=255, blank=True, null=True)  # Razorpay Payment ID
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)  # Razorpay Signature
    
    def save(self, *args, **kwargs):
        # Existing calculation logic
        base_price = self.service.price
        day_rate = Decimal('0.00')

        if self.service.category == 'Venue':
            venue_service = self.service.venue_services.first()
            if venue_service:
                day_rate = venue_service.day_rate
        elif self.service.category == 'Photography':
            photo_service = self.service.photography_services.first()
            if photo_service:
                day_rate = photo_service.base_price

        if day_rate > Decimal('0.00'):
            self.total_amount = day_rate * self.num_days
        else:
            self.total_amount = base_price * self.num_days

        self.booking_amount = self.total_amount * Decimal('0.5')

        # Set default terms and conditions if not provided
        if not self.terms_and_conditions:
            self.terms_and_conditions = self.get_default_terms_and_conditions()

        super().save(*args, **kwargs)

    def get_default_terms_and_conditions(self):
        return """
        <ol>
            <li>Booking Confirmation: The booking is confirmed upon receipt of the 50% booking amount.</li>
            <li>Cancellation Policy: Cancellations made 30 days or more before the event date are eligible for a full refund of the booking amount. Cancellations made less than 30 days before the event date are not eligible for a refund.</li>
            <li>Changes to Booking: Any changes to the booking must be made in writing and are subject to availability and additional charges if applicable.</li>
            <li>Payment: The remaining balance is due 7 days before the event date.</li>
            <li>Service Delivery: The service provider will deliver the services as described in the booking details. Any additional services requested may incur extra charges.</li>
            <li>Force Majeure: The service provider is not liable for failure to perform due to circumstances beyond their control (e.g., natural disasters, pandemics).</li>
            <li>Liability: The service provider's liability is limited to the total amount paid for the services.</li>
            <li>Intellectual Property: All intellectual property rights in relation to the services provided remain with the service provider.</li>
            <li>Dispute Resolution: Any disputes shall be resolved through mediation or arbitration before resorting to legal action.</li>
            <li>Governing Law: This agreement is governed by the laws of India.</li>
        </ol>
        """

    def __str__(self):
        return f"{self.user.name} booked {self.service.name} for {self.event_name} on {self.event_date}"

class ReferenceImage(models.Model):
    image = models.ImageField(upload_to='reference_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Reference Image {self.id}"


# Favorite Model
class Favorite(models.Model):
    user = models.ForeignKey(UserSignup, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    fav_status = models.BooleanField(default=True)
    class Meta:
        unique_together = ('user', 'service')

    def __str__(self):
        return f"{self.user.username} favorited {self.service.name}"

class VendorImage(models.Model):
    vendor_profile = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='vendor_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    venimg_status = models.BooleanField(default=True)  # Status field (0 for inactive, 1 for active)

    def __str__(self):
        return f"Image for {self.vendor_profile.company_name or self.vendor_profile.user.name}"
    




@receiver(post_save, sender=UserSignup)
def assign_predefined_tasks(sender, instance, created, **kwargs):
    if created and instance.role == 'user':
        predefined_tasks = WeddingTask.objects.filter(is_predefined=True, user=None)
        for task in predefined_tasks:
            WeddingTask.objects.create(
                user=instance,
                description=task.description,
                task_month=task.task_month,
                is_predefined=False,
            )

# Signal to notify users about task updates
'''
@receiver(post_save, sender=WeddingTask)
def notify_user_task_status(sender, instance, created, **kwargs):
    if instance.user:
        if created:
            message = f"A new task '{instance.description}' has been added to your wedding plan."
        else:
            if instance.is_completed:
                message = f"Congratulations! You've completed the task '{instance.description}'."
            else:
                message = f"You have an upcoming task: '{instance.description}'. Don't forget to complete it."

        send_mail(
            'Task Notification',
            message,
            'from@example.com',
            [instance.user.email],
            fail_silently=False,
        )
        '''