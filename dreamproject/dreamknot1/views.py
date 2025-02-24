from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.hashers import make_password, check_password
from .models import UserSignup, UserProfile, VendorProfile,WeddingTask,RSVPInvitation, VendorImage,Favorite, Booking, WeddingBudget, BudgetAllocation, WeddingEvent
from django_countries import countries
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.urls import reverse
from datetime import timedelta
from datetime import datetime
from datetime import date
from django.contrib.auth.decorators import login_required
import re
from django.contrib.auth import logout
from django.views.decorators.cache import cache_control
from django.utils import timezone

from django.core.files.storage import FileSystemStorage
from django.core.exceptions import ValidationError
from django.db.models import Avg
from .models import Service, ServiceImage, Rating

from django.db.models import Count
from django.shortcuts import render
from .models import Service  # Make sure to import your Service model

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def index(request):
    # Count and group services by category
    categories_count = Service.objects.values('category').annotate(count=Count('id'))
    
    # Icon mapping for categories
       # Icon mapping for categories
    # Icon mapping for categories
    icon_mapping = {
        'Venue': 'fa-map-marker-alt',  # Corrected to match your category names
        'Photography': 'fa-camera',  # Corrected to match your category names
        'Catering': 'fa-concierge-bell',  # Already correct
        'Decoration': 'fa-paint-roller',  # Add appropriate icon for Decoration
        'MusicEntertainment': 'fa-music',  # Add appropriate icon for Music & Entertainment
        'MakeupHair': 'fa-magic',  # Already correct
        'Rentals': 'fa-box',  # Add appropriate icon for Rentals
        'MehendiArtist': 'fa-paint-brush',  # Already correct
    }

    # Assign icons to categories
    for category in categories_count:
        category['icon'] = icon_mapping.get(category['category'], 'fa-question-circle')  # Default icon if not found
        if category['icon'] == 'fa-question-circle':
            print(f"Warning: No icon found for category '{category['category']}'")  # Log missing icons
        print(category)  # Debugging line to check the output
    context = {
        'categories_count': categories_count,  # Pass the service counts and icons to the template
    }
    return render(request, 'dreamknot1/index.html', context)

# user home page

from django.core.paginator import Paginator
from django.utils import timezone
from django.shortcuts import render
from .models import UserSignup, UserProfile, Service
from django.db.models import Avg, Count
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_home(request):
    user_name = request.session.get('user_name')
    if not user_name:
        messages.error(request, "You must be logged in to view this page.")
        return redirect('login') 

    user_instance = UserSignup.objects.filter(name=user_name).first()

    time_left = None
    wedding_date = None
    message = None

    if user_instance:
        user_profile, created = UserProfile.objects.get_or_create(user=user_instance)
        wedding_date = getattr(user_profile, 'wedding_date', None)

        if wedding_date:
            now = timezone.now()
            wedding_datetime = timezone.make_aware(
                timezone.datetime.combine(wedding_date, timezone.datetime.min.time())
            )

            if wedding_datetime >= now:
                total_seconds = (wedding_datetime - now).total_seconds()
                days = int(total_seconds // (24 * 3600))
                hours = int((total_seconds % (24 * 3600)) // 3600)
                minutes = int((total_seconds % 3600) // 60)
                seconds = int(total_seconds % 60)

                time_left = f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds left"
            else:
                time_left = "Your wedding date has passed!"
        else:
            message = "Please set your wedding date in your profile."

    # Fetch all active services
    services = Service.objects.filter(status=1, availability=True)

    # Apply location filter by city
    place = request.GET.get('city')
    if place:
        services = services.filter(city__icontains=place)

    # Apply other filters based on query parameters
    category = request.GET.get('category')
    if category:
        services = services.filter(category=category)

   # Price range filtering
    # Price range filtering
    price_range = request.GET.get('price_range')
    if price_range:
        if '-' in price_range:
            min_price, max_price = price_range.split('-')
            services = services.filter(price__gte=Decimal(min_price), price__lte=Decimal(max_price))
        else:
            # This handles the case for '100001+' or any single value
            min_price = Decimal(price_range)
            services = services.filter(price__gte=min_price)


    service_type = request.GET.get('service_type')
    if service_type:
        services = services.filter(service_type=service_type)

    # Apply search filter
    search_query = request.GET.get('search')
    if search_query:
        services = services.filter(name__icontains=search_query)
        

    # Pagination
    paginator = Paginator(services, 12)
    page_number = request.GET.get('page')
    page_services = paginator.get_page(page_number)

    services_with_images = []
    for service in page_services:
        # Calculate average rating from service feedback
        reviews = ServiceFeedback.objects.filter(service=service, status=True)
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
        rating_count = reviews.count()
        
        services_with_images.append({
            'service': service,
            'main_image': service.main_image if service.main_image else None,
            'vendor_company_name': service.vendor.company_name if service.vendor else None,
            'rating': round(float(avg_rating), 1),  # Round to 1 decimal place
            'rating_count': rating_count
        })
    # Add is_paginated to check if the queryset is paginated
    is_paginated = page_services.has_other_pages()

    return render(request, 'dreamknot1/user_home.html', {
        'name': user_name,
        'time_left': time_left,
        'wedding_date': wedding_date,
        'message': message,
        'services_with_images': services_with_images,
        'category': category,
        'price_range': price_range,
        'service_type': service_type,
        'city': place,  # Pass city to the template
        'search_query': search_query,
        'is_paginated': is_paginated,
        'page_obj': page_services,
    })



def readmore(request):
    return render(request, 'dreamknot1/readmore.html')

# vendor home page

from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.db.models import Count  # Ensure Count is imported

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def vendor_home(request):
    user_name = request.session.get('user_name', 'vendor')

    # Count and group services by category for vendor home
    categories_count = Service.objects.values('category').annotate(count=Count('id'))

    # Icon mapping for categories
    icon_mapping = {
        'Venue': 'fa-map-marker-alt',  # Corrected to match your category names
        'Photography': 'fa-camera',  # Corrected to match your category names
        'Catering': 'fa-concierge-bell',  # Already correct
        'Decoration': 'fa-paint-roller',  # Add appropriate icon for Decoration
        'MusicEntertainment': 'fa-music',  # Add appropriate icon for Music & Entertainment
        'MakeupHair': 'fa-magic',  # Already correct
        'Rentals': 'fa-box',  # Add appropriate icon for Rentals
        'MehendiArtist': 'fa-paint-brush',  # Already correct
    }

    # Assign icons to categories
    for category in categories_count:
        category['icon'] = icon_mapping.get(category['category'], 'fa-question-circle')  # Default icon if not found
        if category['icon'] == 'fa-question-circle':
            print(f"Warning: No icon found for category '{category['category']}'")  # Log missing icons
        print(category)  # Debugging line to check the output

    return render(request, 'dreamknot1/vendor_home.html', {
        'name': user_name,
        'categories_count': categories_count,  # Pass the service counts and icons to the template
    })
# for signup

import uuid
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from .models import UserSignup
from django.conf import settings
import re

def signup(request):
    if request.method == 'POST':
        # Extract data from the form
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        re_password = request.POST.get('re_password')
        country = request.POST.get('country')
        state = request.POST.get('state')
        place = request.POST.get('place')
        phone = request.POST.get('phone')
        role = request.POST.get('role')

        # Dictionary to store errors
        errors = {}

        # Name Validation (allowing only alphabets and dots)
        if not re.match(r'^[A-Za-z. ]+$', name):
            messages.error(request, "Name can only contain alphabets, dots, and spaces.")
            errors['name'] = "Invalid name."

        # Email Validation
        if not re.match(r'^[a-zA-Z0-9_.+-]+@gmail\.com$', email):
            messages.error(request, "Please enter a valid Gmail address.")
            errors['email'] = "Invalid Gmail address."

        # Password Validation
        if password != re_password:
            messages.error(request, "Passwords do not match.")
            errors['password'] = "Passwords do not match."
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            errors['password_length'] = "Password too short."
        if not re.search(r'[A-Z]', password):
            messages.error(request, "Password must contain at least one uppercase letter.")
            errors['password_uppercase'] = "Password needs an uppercase letter."
        if not re.search(r'[a-z]', password):
            messages.error(request, "Password must contain at least one lowercase letter.")
            errors['password_lowercase'] = "Password needs a lowercase letter."
        if not re.search(r'[0-9]', password):
            messages.error(request, "Password must contain at least one digit.")
            errors['password_digit'] = "Password needs a digit."
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            messages.error(request, "Password must contain at least one special character.")
            errors['password_special'] = "Password needs a special character."

        # Phone Number Validation
        if not re.match(r'^\+?1?\d{10}$', phone):
            messages.error(request, "Enter a valid phone number with exactly 10 digits.")
            errors['phone'] = "Invalid phone number."

        # Check for existing email
        if UserSignup.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            errors['email_exists'] = "Email already registered."

        # If there are errors, re-render the form with messages
        if errors:
            return render(request, 'dreamknot1/signup.html', {
                'name': name,
                'email': email,
                'password': password,
                're_password': re_password,
                'country': country,
                'state': state,
                'place': place,
                'phone': phone,
                'role': role,
                'countries': countries,  # Assuming you have a list of countries
            })

        # Hash the password before saving
        hashed_password = make_password(password)

        # Generate a unique verification code using uuid
        verification_code = get_random_string(length=64)

        # Save the user with the verification code
        user_signup = UserSignup(
            name=name,
            email=email,
            password=hashed_password,
            country=country,
            state=state,
            place=place,
            phone=phone,
            role=role,
            verification_code=verification_code,  # Store generated verification code
        )
        user_signup.save()

        # Send email with the verification link
        verification_link = request.build_absolute_uri(
            reverse('verify_email', args=[verification_code])
        )
        send_mail(
            'Verify your email',
            f'Please click on this link to verify your email: {verification_link}',
            'from@example.com',  # Replace with your email
            [email],
            fail_silently=False,
        )

        messages.success(request, "Signup successful! Please check your email to verify your account.")
        return redirect('login')

    # For GET requests, render the signup page
    context = {
        'countries': countries,  # Assuming you have a list of countries
    }
    return render(request, 'dreamknot1/signup.html', context)



# for verify email while signup
from django.shortcuts import redirect
from django.contrib import messages
from .models import UserSignup

def verify_email(request, verification_code):
    try:
        user = UserSignup.objects.get(verification_code=verification_code)
        if not user.is_verified:
            user.is_verified = True
            user.verification_code = None  # Clear the verification code after it's used
            user.save()
            messages.success(request, "Your email has been verified successfully!")
        else:
            messages.info(request, "Your email is already verified.")
    except UserSignup.DoesNotExist:
        messages.error(request, "Invalid verification link.")

    return redirect('login')


# for login
from django.contrib.auth.hashers import check_password
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import UserSignup

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = UserSignup.objects.get(email=email)
            print("User found:", user.name)
            print("User Status:", user.status)  # Debugging

            if not user.status:
                messages.error(request, "Your account is deactivated. Please contact the admin.")
                print("Deactivated user attempted to log in.") 
                return redirect('login')

            # Check if the user is verified
            if not user.is_verified:
                messages.error(request, "Please verify your email before logging in. Check your inbox for the verification link.")
                return redirect('login')




            if check_password(password, user.password):
                request.session['user_id'] = user.id
                request.session['user_role'] = user.role
                request.session['user_name'] = user.name
                
                messages.success(request, "Login successful!")
                if user.role == 'admin':
                    return redirect('admin_dashboard')
                elif user.role == 'vendor':
                    return redirect('vendor_home')
                else:
                    return redirect('user_home')
            else:
                messages.error(request, "Invalid email or password.")
                print("Incorrect password for user:", user.name)  # Debugging
                return redirect('login')

        except UserSignup.DoesNotExist:
            messages.error(request, "Invalid email or password.")
            print("User not found for email:", email)  # Debugging
            return redirect('login')

    return render(request, 'dreamknot1/login.html')


#vendor image delete
def delete_vendor_image(request, image_id):
    if not request.session.get('user_id'):
        return redirect('login')

    image = get_object_or_404(VendorImage, id=image_id)
    if request.method == 'POST':
        image.delete()
        messages.success(request, "Image deleted successfully!")
        return redirect('vendor_profile')  # Redirect to the vendor profile page

    return render(request, 'dreamknot1/delete_image.html', {'image': image})

# for forgot password

def forgotpass(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Check if the user exists with the provided email
        user = UserSignup.objects.filter(email=email).first()
        
        if user:
            # Generate a random token for the password reset
            token = get_random_string(20)
            
            # Save token and timestamp for expiration (e.g., valid for 1 hour)
            user.reset_token = token
            user.reset_token_created_at = timezone.now()  # Assuming you have this field in your model
            user.save()

            # Build the password reset link
            reset_link = request.build_absolute_uri(reverse('reset_password', args=[token]))
            
            try:
                # Send an email to the user with the reset link
                send_mail(
                    'Password Reset Request',
                    f'Click the link below to reset your password:\n\n{reset_link}\n\nThis link is valid for 1 hour.',
                    'your-email@example.com',  # Replace with the email address configured in settings.py
                    [email],
                    fail_silently=False,
                )
                
                # Display success message to the user
                messages.success(request, 'Password reset link has been sent to your email.')
                return redirect('login')  # Redirect to login after sending the email

            except Exception as e:
                # Display error message if email sending fails
                messages.error(request, f"Error sending email: {str(e)}")
        else:
            # If no user is found with that email
            messages.error(request, 'No account found with that email.')
    
    # Render the forgot password page
    return render(request, 'dreamknot1/forgotpass.html')

# for reset password
def reset_password(request, token):
    # Find the user by the reset token
    user = UserSignup.objects.filter(reset_token=token).first()
    
    if user:
        # Check if the token is expired (assuming a 1-hour validity)
        token_age = timezone.now() - user.reset_token_created_at
        if token_age > timedelta(hours=1):
            messages.error(request, 'Reset token has expired.')
            return redirect('forgotpass')

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if new_password == confirm_password:
                # Hash the new password before saving it
                user.password = make_password(new_password)
                
                # Clear the reset token after successful reset
                user.reset_token = None
                user.reset_token_created_at = None  # Optional, for security
                user.save()

                # Show success message and redirect to login
                messages.success(request, 'Password reset successful. You can now log in.')
                return redirect('login')
            else:
                # Show error if passwords do not match
                messages.error(request, 'Passwords do not match.')
        
        # Render the reset password page if the request method is GET
        return render(request, 'dreamknot1/reset_password.html', {'token': token})
    else:
        # If the token is invalid or expired
        messages.error(request, 'Invalid or expired reset token.')
        return redirect('forgotpass')
    

# for logout

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_view(request):
    request.session.flush()  # Clears all session data
    messages.success(request, "Logged out successfully.")
    return redirect('index')


import re
from django.shortcuts import redirect, render
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from datetime import date
from .models import UserSignup, UserProfile

# Update user profile

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update_user_profile(request):
    if not request.session.get('user_id'):
        return redirect('login')

    user = UserSignup.objects.get(id=request.session['user_id'])
    user_profile, created = UserProfile.objects.get_or_create(user=user)

    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        wedding_date = request.POST.get('wedding_date')
        event_held = request.POST.get('event_held') 
        country = request.POST.get('country')
        state = request.POST.get('state')
        place = request.POST.get('place')

        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        errors = {}

        # Validate email
        if not re.match(r'^[a-zA-Z0-9_.+-]+@gmail\.com$', email):
            messages.error(request, "Please enter a valid Gmail address.")
            errors['email'] = "Invalid Gmail address."

        # Validate wedding_date
        if wedding_date:
            wedding_date_parsed = date.fromisoformat(wedding_date)
            if wedding_date_parsed < date.today():
                errors['wedding_date'] = "Wedding date cannot be in the past."

        if not name:
            errors['name'] = 'Name is required.'
        if not phone or not re.match(r'^\+?1?\d{10}$', phone):
            errors['phone'] = 'Enter a valid phone number with 10 digits.'

        if new_password or confirm_password:
            if new_password != confirm_password:
                errors['password'] = 'Passwords do not match.'
            if len(new_password) < 8:
                errors['password_length'] = "Password must be at least 8 characters long."
            if not re.search(r'[A-Z]', new_password):
                errors['password_uppercase'] = "Password must contain at least one uppercase letter."
            if not re.search(r'[a-z]', new_password):
                errors['password_lowercase'] = "Password must contain at least one lowercase letter."
            if not re.search(r'[0-9]', new_password):
                errors['password_digit'] = "Password must contain at least one digit."
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                errors['password_special'] = "Password must contain at least one special character."

        if errors:
            return render(request, 'dreamknot1/update_user_profile.html', {
                'profile': user_profile,
                'errors': errors,
                'name': name,
                'email': email,
                'phone': phone,
                'wedding_date': wedding_date,
                'event_held': event_held,
                'country': country,
                'state': state,
                'place': place,
                'countries': countries,  # Pass list of countries for dropdown
            })

        # Update user details
        user.name = name
        user.email = email
        user.phone = phone
        user.country = country
        user.state = state
        user.place = place

        if new_password and confirm_password and new_password == confirm_password:
            user.password = make_password(new_password)

        user.save()

        # Update user profile
        user_profile.wedding_date = wedding_date
        user_profile.event_held = event_held   # Save the event_held status
        user_profile.status = True
        user_profile.updated_at = timezone.now()
        user_profile.save()

        messages.success(request, "Profile updated successfully!")
        return redirect('user_home')

    return render(request, 'dreamknot1/update_user_profile.html', {
        'profile': user_profile,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'wedding_date': user_profile.wedding_date,
        'event_held': user_profile.event_held,  # Pre-populate event_held status
        'country': user.country,  # Pre-populate country
        'state': user.state,      # Pre-populate state
        'place': user.place,      # Pre-populate place
        'countries': countries,   # Pass list of countries
    })


import re
from django.shortcuts import redirect, render
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import UserSignup, VendorProfile

# Update vendor profile
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update_vendor_profile(request):
    if not request.session.get('user_id'):
        return redirect('login')

    user_signup = UserSignup.objects.get(id=request.session['user_id'])
    vendor_profile, created = VendorProfile.objects.get_or_create(user=user_signup)

    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        business_category = request.POST.get('business_category')
        company_name = request.POST.get('company_name')
        bio = request.POST.get('bio')
        country = request.POST.get('country')
        state = request.POST.get('state')
        place = request.POST.get('place')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        image = request.FILES.get('image')  # Get the uploaded image

        errors = {}

        # Validate fields as before...

        if errors:
            return render(request, 'dreamknot1/update_vendor_profile.html', {
                'vendor_profile': vendor_profile,
                'errors': errors,
                'name': name,
                'email': email,
                'phone': phone,
                'business_category': business_category,
                'company_name': company_name,
                'bio': bio,
                'country': country,
                'state': state,
                'place': place,
                'countries': countries,
            })

        # Update user details
        user_signup.name = name
        user_signup.email = email
        user_signup.phone = phone
        user_signup.country = country
        user_signup.state = state
        user_signup.place = place

        if new_password and confirm_password and new_password == confirm_password:
            user_signup.password = make_password(new_password)

        user_signup.save()

        # Update vendor profile
        vendor_profile.business_category = business_category
        vendor_profile.company_name = company_name
        vendor_profile.bio = bio
        vendor_profile.status = True
        vendor_profile.save()

        # If an image is uploaded, create a new VendorImage record
        if image:
            VendorImage.objects.create(
                vendor_profile=vendor_profile,
                image=image,
                venimg_status=True  # You can set status based on your requirements
            )

        messages.success(request, "Vendor profile updated successfully!")
        return redirect('vendor_home')

    return render(request, 'dreamknot1/update_vendor_profile.html', {
        'vendor_profile': vendor_profile,
        'name': user_signup.name,
        'email': user_signup.email,
        'phone': user_signup.phone,
        'business_category': vendor_profile.business_category,
        'company_name': vendor_profile.company_name,
        'bio': vendor_profile.bio,
        'country': user_signup.country,
        'state': user_signup.state,
        'place': user_signup.place,
        'countries': countries,
    })

# current month todo list
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import WeddingTask, UserSignup, UserProfile
from django.db.models import Q
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.cache import cache_control


# user view for current month todo list
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def current_month_todolist(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')

    user_instance = get_object_or_404(UserSignup, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user_instance)
    user_name = user_instance.name  # Assuming the username is stored in the 'name' field

    if not user_profile.wedding_date:
        messages.warning(request, "Please set your wedding date to view tasks.")
        return redirect('update_user_profile')

    today = timezone.now().date()
    wedding_date = user_profile.wedding_date
    remaining_days = (wedding_date - today).days

    if remaining_days > 180:
        current_month = '6-12'
        next_month = '4-6'
        days_until_next_month = remaining_days - 180
    elif 120 < remaining_days <= 180:
        current_month = '4-6'
        next_month = '2-4'
        days_until_next_month = remaining_days - 120
    elif 60 < remaining_days <= 120:
        current_month = '2-4'
        next_month = '1-2'
        days_until_next_month = remaining_days - 60
    elif 30 < remaining_days <= 60:
        current_month = '1-2'
        next_month = '1-2 Weeks'
        days_until_next_month = remaining_days - 30
    elif 14 < remaining_days <= 30:
        current_month = '1-2 Weeks'
        next_month = 'Final Days'
        days_until_next_month = remaining_days - 14
    else:
        current_month = 'Final Days'
        next_month = 'Wedding Day'
        days_until_next_month = remaining_days

    # Get user-specific tasks for the current month
    user_tasks = WeddingTask.objects.filter(user=user_instance, task_month=current_month)

    # Check for predefined tasks and create user-specific copies if they don't exist
    predefined_tasks = WeddingTask.objects.filter(user=None, is_predefined=True, task_month=current_month)
    for predefined_task in predefined_tasks:
        if not WeddingTask.objects.filter(user=user_instance, description=predefined_task.description, task_month=current_month).exists():
            WeddingTask.objects.create(
                user=user_instance,
                description=predefined_task.description,
                task_month=current_month,
                is_predefined=False,
                is_completed=False
            )

    # Refresh user tasks after potential additions
    user_tasks = WeddingTask.objects.filter(user=user_instance, task_month=current_month)

    pending_tasks = user_tasks.filter(is_completed=False)
    completed_tasks = user_tasks.filter(is_completed=True)

    if days_until_next_month <= 7 and pending_tasks.exists():
        send_reminder_email(user_instance, current_month, next_month, pending_tasks, days_until_next_month)

    if days_until_next_month < 0 and pending_tasks.exists():
        send_overdue_email(user_instance, current_month, pending_tasks)

    completed_count = completed_tasks.count()
    pending_count = pending_tasks.count()
    overall_completed_count = WeddingTask.objects.filter(user=user_instance, is_completed=True).count()
    overall_pending_count = WeddingTask.objects.filter(user=user_instance, is_completed=False).count()

    return render(request, 'dreamknot1/current_month_todolist.html', {
        'pending_tasks': pending_tasks,
        'completed_tasks': completed_tasks,
        'wedding_month': current_month,
        'today': today,
        'completed_count': completed_count,
        'pending_count': pending_count,
        'overall_completed_count': overall_completed_count,
        'overall_pending_count': overall_pending_count,
        'user_name': user_name,  # Pass the username to the template
    })

# user view for all tasks list
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def todo_list(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')

    user_instance = get_object_or_404(UserSignup, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user_instance)
    user_name = user_instance.name  # Assuming the username is stored in the 'name' field
    

    if not user_profile.wedding_date:
        messages.warning(request, "Please set your wedding date to view tasks.")
        return redirect('update_user_profile')

    remaining_days = (user_profile.wedding_date - timezone.now().date()).days

    # Get user-specific tasks only
    user_tasks = WeddingTask.objects.filter(user=user_instance)

    # Create user-specific copies of predefined tasks if they don't exist
    predefined_tasks = WeddingTask.objects.filter(user=None, is_predefined=True)
    for predefined_task in predefined_tasks:
        if not WeddingTask.objects.filter(user=user_instance, description=predefined_task.description, task_month=predefined_task.task_month).exists():
            WeddingTask.objects.create(
                user=user_instance,
                description=predefined_task.description,
                task_month=predefined_task.task_month,
                is_predefined=False,  # Set to False for user-specific tasks
                is_completed=False
            )

    # Group tasks by month
    tasks_by_month = {}
    for task in user_tasks:
        if task.task_month not in tasks_by_month:
            tasks_by_month[task.task_month] = []
        tasks_by_month[task.task_month].append(task)

    completed_count = user_tasks.filter(is_completed=True).count()
    pending_count = user_tasks.filter(is_completed=False).count()

    context = {
        'tasks': tasks_by_month,
        'completed_count': completed_count,
        'pending_count': pending_count,
        'user_name': user_name,  # Pass the username to the template
    }

    return render(request, 'dreamknot1/todo_list.html', context)


# useradd task
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_task(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to add a task.")
        return redirect('login')

    user_instance = get_object_or_404(UserSignup, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user_instance)

    if not user_profile.wedding_date:
        messages.error(request, "Please set your wedding date first.")
        return redirect('set_wedding_date')

    if request.method == 'POST':
        task_description = request.POST.get('task_description')
        task_month = request.POST.get('task_month')

        if task_description:
            WeddingTask.objects.create(
                user=user_instance,
                description=task_description,
                task_month=task_month
            )
            messages.success(request, "Task added successfully.")
            return redirect('todo_list')
        else:
            messages.error(request, "Task description cannot be empty.")

    return render(request, 'dreamknot1/add_task.html')


# user view for update task
def update_task(request, task_id):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to update a task.")
        return redirect('login')

    task = get_object_or_404(WeddingTask, id=task_id, user__id=user_id)

    if request.method == 'POST':
        task.is_completed = not task.is_completed
        task.save()
        messages.success(request, "Task updated successfully.")
          # Determine which page to redirect to
        referer = request.META.get('HTTP_REFERER', '')
        if 'current' in referer:
            return redirect('current_month_todolist')
        else:
            return redirect('todo_list')

    return render(request, 'dreamknot1/update_task.html', {'task': task})


# user view for delete task
def delete_task(request, task_id):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to delete a task.")
        return redirect('login')

    task = get_object_or_404(WeddingTask, id=task_id)

    if task.user is None:
        messages.error(request, "Predefined tasks cannot be deleted.")
        return redirect('todo_list')

    if task.user_id != user_id:
        messages.error(request, "You can only delete your own tasks.")
        return redirect('todo_list')

    task.delete()
    messages.success(request, "Task deleted successfully.")
    return redirect('todo_list')

# user view for send reminder email of task
def send_reminder_email(user, current_month, next_month, pending_tasks, days_left):
    subject = f"Reminder: Complete your {current_month} wedding tasks"
    message = f"Hello {user.name},\n\n"
    message += f"You have {days_left} days left to complete your {current_month} wedding tasks before moving to the {next_month} phase.\n\n"
    message += "Here are your pending tasks:\n\n"
    for task in pending_tasks:
        message += f"- {task.description}\n"
    message += "\nPlease complete these tasks as soon as possible to stay on track with your wedding planning.\n\n"
    message += "Best regards,\nDream Knot Team"

    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )

# user view for send overdue email of task

def send_overdue_email(user, current_month, pending_tasks):
    subject = f"Urgent: Overdue {current_month} wedding tasks"
    message = f"Hello {user.name},\n\n"
    message += f"Your {current_month} wedding tasks are now overdue. Please complete them as soon as possible.\n\n"
    message += "Here are your overdue tasks:\n\n"
    for task in pending_tasks:
        message += f"- {task.description}\n"
    message += "\nCompleting these tasks is crucial for staying on track with your wedding planning.\n\n"
    message += "Best regards,\nDream Knot Team"

    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )

import csv
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import RSVPInvitation
from django.core.mail import send_mail
from django.urls import reverse
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.utils.encoding import smart_str
from io import TextIOWrapper
from django.core.exceptions import ValidationError

# user view for send e-invitation
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def send_rsvp_invitation(request):
    if not request.session.get('user_id'):
        return redirect('login')

    couple = UserSignup.objects.get(id=request.session['user_id'])
    user_name = couple.name  # Assuming the username is stored in the 'name' field

    if request.method == "POST":
        guest_names = request.POST.getlist("guest_name[]")  # Expecting multiple names
        guest_emails = request.POST.getlist("guest_email[]")  # Expecting multiple emails
        event_name = request.POST.get("event_name")
        event_date = request.POST.get("event_date")
        event_time = request.POST.get("event_time")
        event_description = request.POST.get("event_description")
        venue = request.POST.get("venue")
        venue_address = request.POST.get("venue_address")
        phone_number = request.POST.get("phone_number")
        location_link = request.POST.get("location_link")
        csv_file = request.FILES.get('guest_upload')  # Uploaded CSV file

        success = True  # Flag to track if all invitations were sent successfully


        if csv_file:
            try:
                # Handle CSV file upload for bulk guest entries
                csv_file = TextIOWrapper(csv_file.file, encoding='utf-8')
                reader = csv.reader(csv_file)

                for row in reader:
                    if len(row) != 2:
                        raise ValidationError("Invalid CSV format. Each row must have exactly two columns: Name and Email.")

                    guest_name, guest_email = row
                    # Create and send the invitation for each guest in CSV
                    send_invitation(couple, event_name, event_date, event_time, event_description,
                                    venue, venue_address, phone_number, location_link, guest_name, guest_email)

            except ValidationError as e:
                messages.error(request, str(e))
                return redirect('send_rsvp_invitation')

            except Exception as e:
                messages.error(request, 'Error processing CSV file. Please ensure the format is correct.')
                return redirect('send_rsvp_invitation')

        # Handle manual guest entry from the form
        for guest_name, guest_email in zip(guest_names, guest_emails):
            send_invitation(couple, event_name, event_date, event_time, event_description,
                            venue, venue_address, phone_number, location_link, guest_name, guest_email)

        if success:
            messages.success(request, 'Invitations sent successfully to all guests!')
            return redirect('send_rsvp_invitation')
        
    context = {
        'user_name': user_name,
        # Add any other context variables you need
    }
    return render(request, 'dreamknot1/send_rsvp_invitation.html', context)

# user view for send invitation
def send_invitation(couple, event_name, event_date, event_time, event_description, venue, venue_address, phone_number, location_link, guest_name, guest_email):
    """
    Helper function to create the invitation entry and send an email.
    """
    # Create the RSVP invitation entry
    invitation = RSVPInvitation.objects.create(
        couple=couple,
        couple_name=couple.name,
        event_name=event_name,
        guest_name=guest_name,
        guest_email=guest_email,
        event_date=event_date,
        event_time=event_time,
        event_description=event_description,
        venue=venue,
        venue_address=venue_address,
        phone_number=phone_number,
        location_link=location_link,
    )

    # Prepare the HTML email content
    html_message = render_to_string('dreamknot1/email_invitation.html', {
        'couple_name': couple.name,
        'event_name': event_name,
        'event_date': event_date,
        'event_time': event_time,
        'event_description': event_description,
        'venue': venue,
        'venue_address': venue_address,
        'phone_number': phone_number,
        'location_link': location_link,
        'guest_name': guest_name,  # Customize the email for each guest
    })

    # Send the HTML email to each guest
    send_mail(
        f"Invitation to {event_name} from {couple.name}",
        '',
        'noreply@dreamknot.com',
        [guest_email],
        html_message=html_message,
        fail_silently=False,
    )

from django.shortcuts import render, redirect
from .models import UserSignup, RSVPInvitation

# user view for invitation list
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def invitation_list(request):
    if not request.session.get('user_id'):
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')

    couple = UserSignup.objects.get(id=request.session['user_id'])
    user_name = couple.name  # Fetch the username (assuming it's stored in the 'name' field)

    invitations = RSVPInvitation.objects.filter(couple=couple).order_by('event_name', 'event_date')

    # Group invitations by event name
    grouped_invitations = {}
    for invitation in invitations:
        if invitation.event_name not in grouped_invitations:
            grouped_invitations[invitation.event_name] = {
                'invitations': [],
                'event_date': invitation.event_date,
                'venue': invitation.venue
            }
        grouped_invitations[invitation.event_name]['invitations'].append(invitation)
 
    context = { 
        'user_name': user_name,  # Pass the username to the template
        'grouped_invitations': grouped_invitations,
    }
    return render(request, 'dreamknot1/invitation_list.html', context)

def rsvp_success(request):
    return render(request, 'dreamknot1/rsvp_success.html')

from django.shortcuts import render, redirect
from django.utils import timezone
from django.http import HttpResponse
from .models import VendorProfile, Service, ServiceImage, Booking, Rating, Favorite



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.db import transaction
from decimal import Decimal, InvalidOperation
from .models import (
    VendorProfile, Service, ServiceImage, VenueService, CateringService,
    PhotographyService, MusicEntertainmentService, MakeupHairService,
    RentalsService, MehendiArtistService, DecorationService, Booking
)
import re
def parse_boolean(value):
    return value == 'on' or value == 'true' or value == 'True' or value is True

# vendor view for vendor dashboard
def vendor_dashboard(request):
    vendor_name = request.session.get('user_name', 'vendor')

    try:
        vendor_instance = VendorProfile.objects.get(user__name=vendor_name)

        if not vendor_instance.company_name or not vendor_instance.bio or not vendor_instance.business_category:
            messages.warning(request, "Please complete your profile before accessing the dashboard.")
            return redirect('update_vendor_profile')

    except VendorProfile.DoesNotExist:
        messages.warning(request, "Vendor not found. Please add your details in the profile first.")
        return redirect('update_vendor_profile')

    services = Service.objects.filter(vendor=vendor_instance)
    bookings = Booking.objects.filter(service__in=services)

    errors = {}
    service_data = {
        'name': '',
        'description': '',
        'price': '',
        'category': '',
        'city': '',
        'availability': False,
        'additional_fields': {},
        'brochure': None,
    }

    if request.method == "POST":
        service_data['name'] = request.POST.get('name', '')
        service_data['description'] = request.POST.get('description', '')
        service_data['price'] = request.POST.get('price', '')
        service_data['category'] = request.POST.get('category', '')
        service_data['city'] = request.POST.get('city', '')
        service_data['availability'] = 'availability' in request.POST
        service_data['brochure'] = request.FILES.get('brochure', None)

        # Validate general service fields
        if not re.match(r'^[A-Za-z\s]+$', service_data['name']):
            errors['name'] = "Service name can only contain alphabets and spaces."
        if not service_data['price']:
            errors['price'] = "Price is required."
        else:
            try:
                price_value = float(service_data['price'])
                if price_value <= 0:
                    errors['price'] = "Price must be a positive number."
            except ValueError:
                errors['price'] = "Invalid price format."
        if Service.objects.filter(vendor=vendor_instance, name=service_data['name']).exists():
            errors['name'] = f"A service with the name '{service_data['name']}' already exists."

        # Save the service object if no errors
        if not errors:
            try:
                with transaction.atomic():
                    service = Service.objects.create(
                        vendor=vendor_instance,
                        name=service_data['name'],
                        description=service_data['description'],
                        price=service_data['price'],
                        category=service_data['category'],
                        city=service_data['city'],
                        created_at=timezone.now(),
                        availability=service_data['availability'],
                        brochure=service_data['brochure']
                    )

                    # Handle the main service image (single image)
                    if 'main_image' in request.FILES:
                        service.main_image = request.FILES['main_image']
                        service.save()

                    # Handle multiple service images
                    if 'service_images' in request.FILES:
                        for image in request.FILES.getlist('service_images'):
                            ServiceImage.objects.create(service=service, image=image)

                    # Sub-service handling based on service type
                    if service_data['category'] == 'Venue':
                        VenueService.objects.create(
                            service=service,
                            type_of_venue=request.POST.get('type_of_venue', ''),
                            location=request.POST.get('location', ''),
                            capacity=request.POST.get('capacity', ''),
                            pre_post_wedding_availability=parse_boolean(request.POST.get('pre_post_wedding_availability')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                            day_rate=float(request.POST.get('day_rate', 0.00)),
                            setup_fee=float(request.POST.get('setup_fee', 0.00)),
                        )
                    elif service_data['category'] == 'Catering':
                        CateringService.objects.create(
                            service=service,
                            menu_planning=request.POST.get('menu_planning', ''),
                            meal_service_type=request.POST.get('meal_service_type', ''),
                            dietary_options=request.POST.get('dietary_options', ''),
                            price_per_person=float(request.POST.get('price_per_person', 0.00)),
                            setup_fee=float(request.POST.get('setup_fee', 0.00)),
                            minimum_guest_count=int(request.POST.get('minimum_guest_count', 1)),
                        )
                    elif service_data['category'] == 'Photography':
                        PhotographyService.objects.create(
                            service=service,
                            package_duration=request.POST.get('package_duration', ''),
                            styles=request.POST.get('styles', ''),
                            engagement_shoots=parse_boolean(request.POST.get('engagement_shoots')),
                            videography_options=parse_boolean(request.POST.get('videography_options')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                        )
                    elif service_data['category'] == 'MusicEntertainment':
                        MusicEntertainmentService.objects.create(
                            service=service,
                            entertainment_options=request.POST.get('entertainment_options', ''),
                            sound_system_setup=parse_boolean(request.POST.get('sound_system_setup')),
                            multiple_entertainment_acts=parse_boolean(request.POST.get('multiple_entertainment_acts')),
                            emcee_services=parse_boolean(request.POST.get('emcee_services')),
                            playlist_customization=parse_boolean(request.POST.get('playlist_customization')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                        )
                    elif service_data['category'] == 'MakeupHair':
                        MakeupHairService.objects.create(
                            service=service,
                            grooming_services=request.POST.get('grooming_services', ''),
                            trial_sessions=parse_boolean(request.POST.get('trial_sessions')),
                            high_end_products=parse_boolean(request.POST.get('high_end_products')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                        )
                    elif service_data['category'] == 'Rentals':
                        RentalsService.objects.create(
                            service=service,
                            rental_items=request.POST.get('rental_items', ''),
                            setup_services=parse_boolean(request.POST.get('setup_services')),
                            rental_price_per_item=float(request.POST.get('rental_price_per_item', 0.00)),
                            deposit_required=float(request.POST.get('deposit_required', 0.00)),
                            duration_of_rental=request.POST.get('duration_of_rental', ''),
                        )
                    elif service_data['category'] == 'MehendiArtist':
                        MehendiArtistService.objects.create(
                            service=service,
                            design_styles=request.POST.get('design_styles', ''),
                            duration_per_hand=float(request.POST.get('duration_per_hand', 0.00)),
                            use_of_organic_henna=parse_boolean(request.POST.get('use_of_organic_henna')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                        )
                    elif service_data['category'] == 'Decoration':
                        DecorationService.objects.create(
                            service=service,
                            decor_themes=request.POST.get('decor_themes', ''),
                            floral_arrangements=parse_boolean(request.POST.get('floral_arrangements')),
                            lighting_options=parse_boolean(request.POST.get('lighting_options')),
                            stage_decor=parse_boolean(request.POST.get('stage_decor')),
                            base_price=float(request.POST.get('base_price', 0.00)),
                            hourly_rate=float(request.POST.get('hourly_rate', 0.00)),
                        )

                    messages.success(request, f"{service_data['category']} service has been successfully created!")

            except Exception as e:
                messages.error(request, f"An error occurred while creating the service: {str(e)}")
        else:
            messages.error(request, "There were errors in the form submission. Please check your inputs.")

    return render(request, 'dreamknot1/vendor_dashboard.html', {
        'vendor': vendor_instance,
        'services': services,
        'bookings': bookings,
        'errors': errors,
        'service_data': service_data,
        'categories': Service.CATEGORY_CHOICES,
    })
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.db import transaction
from decimal import Decimal, InvalidOperation
from .models import (
    VendorProfile, Service, ServiceImage, VenueService, CateringService,
    PhotographyService, MusicEntertainmentService, MakeupHairService,
    RentalsService, MehendiArtistService, DecorationService
)
from django.http import HttpResponse
import re

def parse_boolean(value):
    return value in ['on', 'true', 'True', True]

def parse_decimal(value, default=0):
    try:
        return Decimal(value) if value else Decimal(default)
    except InvalidOperation:
        raise ValueError(f"Invalid decimal value: {value}")

# vendor view for edit service
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_service(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    vendor_name = request.session.get('user_name', 'vendor')
    
    if service.vendor.user.name != vendor_name:
        return HttpResponse("You do not have permission to edit this service.")

    errors = {}
    service_data = {
        'name': service.name,
        'description': service.description,
        'price': service.price,
        'category': service.category,
        'city': service.city,
        'availability': service.availability,
        'brochure': service.brochure,
    }

    if request.method == "POST":
        service_data['name'] = request.POST.get('name', '')
        service_data['description'] = request.POST.get('description', '')
        service_data['price'] = request.POST.get('price', '')
        service_data['category'] = request.POST.get('category', '')
        service_data['city'] = request.POST.get('city', '')
        service_data['availability'] = 'availability' in request.POST
        service_data['brochure'] = request.FILES.get('brochure', service.brochure)

        # Validate general service fields
        if not re.match(r'^[A-Za-z\s]+$', service_data['name']):
            errors['name'] = "Service name can only contain alphabets and spaces."
        if not service_data['price']:
            errors['price'] = "Price is required."
        else:
            try:
                price_value = float(service_data['price'])
                if price_value <= 0:
                    errors['price'] = "Price must be a positive number."
            except ValueError:
                errors['price'] = "Invalid price format."

        if not errors:
            try:
                with transaction.atomic():
                    # Update main Service fields
                    service.name = service_data['name']
                    service.description = service_data['description']
                    service.price = Decimal(service_data['price'])
                    service.category = service_data['category']
                    service.city = service_data['city']
                    service.availability = service_data['availability']
                    service.brochure = service_data['brochure']
                    service.updated_at = timezone.now()
                    service.save()

                    # Handle main image update
                    if 'main_image' in request.FILES:
                        service.main_image = request.FILES['main_image']
                        service.save()

                    # Handle additional images
                    new_images = request.FILES.getlist('new_service_images')
                    for image in new_images:
                        ServiceImage.objects.create(service=service, image=image)
                    
                    # Update category-specific fields
                    if service.category == 'Venue':
                        venue_service, created = VenueService.objects.get_or_create(service=service)
                        venue_service.type_of_venue = request.POST.get('type_of_venue', '')
                        venue_service.location = request.POST.get('location', '')
                        venue_service.capacity = int(request.POST.get('capacity', 0))
                        venue_service.pre_post_wedding_availability = parse_boolean(request.POST.get('pre_post_wedding_availability'))
                        venue_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        venue_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        venue_service.day_rate = parse_decimal(request.POST.get('day_rate', 0))
                        venue_service.setup_fee = parse_decimal(request.POST.get('setup_fee', 0))
                        venue_service.save()

                    elif service.category == 'Catering':
                        catering_service, created = CateringService.objects.get_or_create(service=service)
                        catering_service.menu_planning = request.POST.get('menu_planning', '')
                        catering_service.meal_service_type = request.POST.get('meal_service_type', '')
                        catering_service.dietary_options = request.POST.get('dietary_options', '')
                        catering_service.price_per_person = parse_decimal(request.POST.get('price_per_person', 0))
                        catering_service.setup_fee = parse_decimal(request.POST.get('setup_fee', 0))
                        catering_service.minimum_guest_count = int(request.POST.get('minimum_guest_count', 1))
                        catering_service.save()

                    elif service.category == 'Photography':
                        photo_service, created = PhotographyService.objects.get_or_create(service=service)
                        photo_service.package_duration = request.POST.get('package_duration', '')
                        photo_service.styles = request.POST.get('styles', '')
                        photo_service.engagement_shoots = parse_boolean(request.POST.get('engagement_shoots'))
                        photo_service.videography_options = parse_boolean(request.POST.get('videography_options'))
                        photo_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        photo_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        photo_service.save()

                    elif service.category == 'MusicEntertainment':
                        music_service, created = MusicEntertainmentService.objects.get_or_create(service=service)
                        music_service.entertainment_options = request.POST.get('entertainment_options', '')
                        music_service.sound_system_setup = parse_boolean(request.POST.get('sound_system_setup'))
                        music_service.multiple_entertainment_acts = parse_boolean(request.POST.get('multiple_entertainment_acts'))
                        music_service.emcee_services = parse_boolean(request.POST.get('emcee_services'))
                        music_service.playlist_customization = parse_boolean(request.POST.get('playlist_customization'))
                        music_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        music_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        music_service.save()

                    elif service.category == 'MakeupHair':
                        makeup_service, created = MakeupHairService.objects.get_or_create(service=service)
                        makeup_service.grooming_services = request.POST.get('grooming_services', '')
                        makeup_service.trial_sessions = parse_boolean(request.POST.get('trial_sessions'))
                        makeup_service.high_end_products = parse_boolean(request.POST.get('high_end_products'))
                        makeup_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        makeup_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        makeup_service.save()

                    elif service.category == 'Rentals':
                        rental_service, created = RentalsService.objects.get_or_create(service=service)
                        rental_service.rental_items = request.POST.get('rental_items', '')
                        rental_service.setup_services = parse_boolean(request.POST.get('setup_services'))
                        rental_service.rental_price_per_item = parse_decimal(request.POST.get('rental_price_per_item', 0))
                        rental_service.deposit_required = parse_decimal(request.POST.get('deposit_required', 0))
                        rental_service.duration_of_rental = request.POST.get('duration_of_rental', '')
                        rental_service.save()

                    elif service.category == 'MehendiArtist':
                        mehendi_service, created = MehendiArtistService.objects.get_or_create(service=service)
                        mehendi_service.design_styles = request.POST.get('design_styles', '')
                        mehendi_service.duration_per_hand = parse_decimal(request.POST.get('duration_per_hand', 0))
                        mehendi_service.use_of_organic_henna = parse_boolean(request.POST.get('use_of_organic_henna'))
                        mehendi_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        mehendi_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        mehendi_service.save()

                    elif service.category == 'Decoration':
                        decor_service, created = DecorationService.objects.get_or_create(service=service)
                        decor_service.decor_themes = request.POST.get('decor_themes', '')
                        decor_service.floral_arrangements = parse_boolean(request.POST.get('floral_arrangements'))
                        decor_service.lighting_options = parse_boolean(request.POST.get('lighting_options'))
                        decor_service.stage_decor = parse_boolean(request.POST.get('stage_decor'))
                        decor_service.base_price = parse_decimal(request.POST.get('base_price', 0))
                        decor_service.hourly_rate = parse_decimal(request.POST.get('hourly_rate', 0))
                        decor_service.save()

                messages.success(request, f"{service.category} service has been successfully updated!")
                return redirect('vendor_dashboard')

            except Exception as e:
                messages.error(request, f"An error occurred while updating the service: {str(e)}")
        else:
            for key, value in errors.items():
                messages.error(request, value)

    # Prepare context for rendering the edit form
    context = {
        'service': service,
        'categories': Service.CATEGORY_CHOICES,
        'errors': errors,
        'service_data': service_data,
        'vendor_name': vendor_name,  # Add vendor_name to context
    }

    # Add category-specific data to the context
    if service.category == 'Venue':
        context['venue_service'] = VenueService.objects.get_or_create(service=service)[0]
    elif service.category == 'Catering':
        context['catering_service'] = CateringService.objects.get_or_create(service=service)[0]
    elif service.category == 'Photography':
        context['photo_service'] = PhotographyService.objects.get_or_create(service=service)[0]
    elif service.category == 'MusicEntertainment':
        context['music_service'] = MusicEntertainmentService.objects.get_or_create(service=service)[0]
    elif service.category == 'MakeupHair':
        context['makeup_service'] = MakeupHairService.objects.get_or_create(service=service)[0]
    elif service.category == 'Rentals':
        context['rental_service'] = RentalsService.objects.get_or_create(service=service)[0]
    elif service.category == 'MehendiArtist':
        context['mehendi_service'] = MehendiArtistService.objects.get_or_create(service=service)[0]
    elif service.category == 'Decoration':
        context['decor_service'] = DecorationService.objects.get_or_create(service=service)[0]

    return render(request, 'dreamknot1/edit_service.html', context)

# vendor view for delete service
def delete_service(request, service_id):
    try:
        service = Service.objects.get(id=service_id)
        service.delete()
        return redirect('vendor_dashboard')
    except Service.DoesNotExist:
        return HttpResponse("Service not found.")
    

# vendor view for delete service image
from django.http import JsonResponse
from django.views.decorators.http import require_POST

@require_POST
def delete_service_image(request, image_id):
    try:
        image = ServiceImage.objects.get(id=image_id)
        image.delete()
        return JsonResponse({'status': 'success'})
    except ServiceImage.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Image not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)  


# for user name display in user navigation bar
def user_name(request):
    user_name = request.session.get('user_name', '')
    return {'user_name': user_name}


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_dashboard(request):
    user_name = request.session.get('user_name', 'user')
    if not user_name:
        messages.error(request, "You must be logged in to view this page.")
        return redirect('login')
    
    # Fetch the user from session
    try:
        user = UserSignup.objects.get(name=user_name)
    except UserSignup.DoesNotExist:
        return HttpResponse("User not found.")

    # Fetch active services
    services = Service.objects.filter(status=1, availability=True)

    # Filter services by category
    if 'category' in request.GET:
        category = request.GET['category']
        services = services.filter(category=category)

    # Search services
    if 'search' in request.GET:
        search_query = request.GET['search']
        services = services.filter(name__icontains=search_query)

    # Fetch favorite services for the logged-in user
    favorites = Favorite.objects.filter(user=user).values_list('service_id', flat=True)
    
   # Get vendors and related services
    vendor_services = {}
    for service in services:
        vendor = service.vendor
        # Calculate average rating from service feedback
        reviews = ServiceFeedback.objects.filter(service=service, status=True)
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
        rating_count = reviews.count()
        
        # Add a flag to indicate if the service is liked
        service.is_liked = service.id in favorites
        # Add rating information
        service.rating = round(float(avg_rating), 1)
        service.rating_count = rating_count
        vendor_services.setdefault(vendor, []).append(service)

    # Fetch bookings for the logged-in user
    bookings = Booking.objects.filter(user=user).select_related('service')

    return render(request, 'dreamknot1/user_dashboard.html', {
        'vendor_services': vendor_services,
        'user_name': user_name,
        'favorites': favorites,
        'bookings': bookings,
        'category': category if 'category' in request.GET else None,  # Pass the category to the template
    })

# user view for vendor services
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def vendor_services(request, vendor_id):
    user_name = request.session.get('user_name', '')
    if not user_name:
        messages.error(request, "You must be logged in to view this page.")
        return redirect('login')
    
    vendor = get_object_or_404(VendorProfile, id=vendor_id)
    services = Service.objects.filter(vendor=vendor, status=1, availability=True)
    return render(request, 'dreamknot1/vendor_services.html', {
        'vendor': vendor, 
        'services': services,
        'user_name': user_name
    })
from django.shortcuts import render, get_object_or_404
from .models import (
    Service, VenueService, CateringService, PhotographyService, 
    MusicEntertainmentService, MakeupHairService, RentalsService, 
    MehendiArtistService, DecorationService, ServiceFeedback
)
from django.db.models import Avg, Count, Max
from django.core.paginator import Paginator

# user view for service detail
from django.shortcuts import render, get_object_or_404
from .models import Service, VenueService, CateringService, PhotographyService, MusicEntertainmentService, MakeupHairService, RentalsService, MehendiArtistService, DecorationService
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def service_detail(request, service_id):
    user_name = request.session.get('user_name', '')
    if not user_name:
        messages.error(request, "You must be logged in to view this page.")
        return redirect('login')

    service = get_object_or_404(Service, id=service_id)
    vendor_phone = service.vendor.user.phone

    # Get category-specific details
    category_details = None
    if service.category == 'Venue':
        category_details = VenueService.objects.filter(service=service).first()
    elif service.category == 'Catering':
        category_details = CateringService.objects.filter(service=service).first()
    elif service.category == 'Photography':
        category_details = PhotographyService.objects.filter(service=service).first()
    elif service.category == 'MusicEntertainment':
        category_details = MusicEntertainmentService.objects.filter(service=service).first()
    elif service.category == 'MakeupHair':
        category_details = MakeupHairService.objects.filter(service=service).first()
    elif service.category == 'Rentals':
        category_details = RentalsService.objects.filter(service=service).first()
    elif service.category == 'MehendiArtist':
        category_details = MehendiArtistService.objects.filter(service=service).first()
    elif service.category == 'Decoration':
        category_details = DecorationService.objects.filter(service=service).first()

# Get reviews with user information
    reviews = ServiceFeedback.objects.filter(service=service).select_related('user', 'sentiment').order_by('-created_at')
    total_reviews = reviews.count()
    
    # Calculate average rating and rating distribution
    avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
    
    # Use string keys for rating_distribution
    rating_distribution = {
        '5': reviews.filter(rating=5).count(),
        '4': reviews.filter(rating=4).count(),
        '3': reviews.filter(rating=3).count(),
        '2': reviews.filter(rating=2).count(),
        '1': reviews.filter(rating=1).count()
    }
    
    # Calculate rating percentages
    rating_percentages = {}
    if total_reviews > 0:
        for rating in ['5', '4', '3', '2', '1']:
            count = rating_distribution[rating]
            rating_percentages[rating] = round((count / total_reviews) * 100, 1)
    else:
        # If no reviews, set all percentages to 0
        for rating in ['5', '4', '3', '2', '1']:
            rating_percentages[rating] = 0.0

      # Group reviews by user
    user_reviews = reviews.values('user').annotate(
        review_count=Count('id'),
        latest_review=Max('created_at')
    ).order_by('-latest_review')

    # Pagination
    paginator = Paginator(list(user_reviews), 10)  # Show 10 users per page
    page = request.GET.get('page', 1)
    user_reviews_page = paginator.get_page(page)

    # Get all reviews for users on current page
    user_ids = [review['user'] for review in user_reviews_page]
    grouped_reviews = {}
    for user_id in user_ids:
        user_reviews = reviews.filter(user=user_id).order_by('-created_at')
        if user_reviews:
            grouped_reviews[user_id] = list(user_reviews)


    context = {
        'service': service,
        'vendor_phone': vendor_phone,
        'category_details': category_details,
        'user_name': user_name,
        'avg_rating': round(avg_rating, 1),
        'rating_distribution': rating_distribution,
        'rating_percentages': rating_percentages,
        'total_reviews': total_reviews,
        'page_obj': user_reviews_page,
        'grouped_reviews': grouped_reviews
    }

    return render(request, 'dreamknot1/service_detail.html', context)



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Count
from django.views.decorators.cache import cache_control
from .models import (
    UserSignup, Service, VenueService, CateringService, PhotographyService, 
    MusicEntertainmentService, MakeupHairService, RentalsService, 
    MehendiArtistService, DecorationService
)

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_service_details(request, service_id):
    # Ensure the user is logged in as an admin
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')

    if not (user_id and user_role == 'admin'):
        messages.error(request, "You must be logged in as an admin to view this page.")
        return redirect('login')

    try:
        admin = UserSignup.objects.get(id=user_id, role='admin', is_super=True)
    except UserSignup.DoesNotExist:
        messages.error(request, "Admin user not found.")
        return redirect('login')

    # Fetch the specific service
    service = get_object_or_404(Service, id=service_id)
    vendor_phone = service.vendor.user.phone

    # Retrieve category-specific details based on the service's category
    category_details = None
    if service.category == 'Venue':
        category_details = VenueService.objects.filter(service=service).first()
    elif service.category == 'Catering':
        category_details = CateringService.objects.filter(service=service).first()
    elif service.category == 'Photography':
        category_details = PhotographyService.objects.filter(service=service).first()
    elif service.category == 'MusicEntertainment':
        category_details = MusicEntertainmentService.objects.filter(service=service).first()
    elif service.category == 'MakeupHair':
        category_details = MakeupHairService.objects.filter(service=service).first()
    elif service.category == 'Rentals':
        category_details = RentalsService.objects.filter(service=service).first()
    elif service.category == 'MehendiArtist':
        category_details = MehendiArtistService.objects.filter(service=service).first()
    elif service.category == 'Decoration':
        category_details = DecorationService.objects.filter(service=service).first()

    # Render the admin service detail view with relevant details
    context = {
        'admin_name': admin.name,
        'service': service,
        'vendor_phone': vendor_phone,
        'category_details': category_details,
    }

    return render(request, 'dreamknot1/admin_service_details.html', context)








from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.utils import timezone
from .models import Booking  # Assuming Booking model is in the same app

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from .models import VendorProfile, Booking, UserSignup, Service
from django.utils import timezone

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def vendor_approve_booking(request):
    user_id = request.session.get('user_id')
    
    if not user_id:
        messages.warning(request, "You need to log in to access this page.")
        return redirect('login')

    try:
        vendor_instance = VendorProfile.objects.get(user__id=user_id)
        bookings = Booking.objects.filter(service__vendor=vendor_instance)

        context = {
            'bookings': bookings,
            'vendor_name': vendor_instance.user.name,
        }
        return render(request, 'dreamknot1/vendor_approve_booking.html', context)

    except VendorProfile.DoesNotExist:
        messages.warning(request, "Vendor profile not found. Please complete your profile.")
        return redirect('update_vendor_profile')





from django.core.mail import EmailMessage
from django.http import JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from .models import VendorProfile, Booking, UserSignup
from django.conf import settings
from django.utils import timezone
@require_POST
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def process_booking(request):
    user_id = request.session.get('user_id')
    
    if not user_id:
        return JsonResponse({'status': 'error', 'message': 'You need to log in to perform this action.'})

    try:
        vendor_instance = VendorProfile.objects.get(user__id=user_id)
        booking_id = request.POST.get('booking_id')
        action = request.POST.get('action')
        
        booking = get_object_or_404(Booking, id=booking_id, service__vendor=vendor_instance)
        user = get_object_or_404(UserSignup, id=booking.user.id)
        
        if action == 'approve':
            booking.book_status = 1  # Approved
            booking.vendor_confirmed_at = timezone.now()
            message = "Your booking has been approved."
            
            # Create the approved booking email
            email_message = create_approved_booking_email(user, booking)
            
            # Send email to user
            email = EmailMessage(
                subject=f"Booking Approved for {booking.service.name}",
                body=email_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            email.content_subtype = "html"  # Specify that the email content is HTML
            email.send(fail_silently=False)  # Send the email

        elif action == 'reject':
            booking.book_status = 3  # Rejected/Cancelled
            booking.vendor_confirmed_at = None
            booking.canceled_by_user = True
            
            # Call the dummy refund method
            refund_success = dummy_refund_payment(booking)
            if not refund_success:
                return JsonResponse({'status': 'error', 'message': 'Refund failed. Please contact support.'})
            
            message = "Your booking has been rejected and the amount has been refunded."
            
            # Create the rejected booking email
            email_message = create_rejected_booking_email(user, booking)
            
            # Send email to user
            email = EmailMessage(
                subject=f"Booking Rejected for {booking.service.name}",
                body=email_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            email.content_subtype = "html"  # Specify that the email content is HTML
            email.send(fail_silently=False)  # Send the email

        elif action == 'complete':
            booking.book_status = 2  # Completed
            message = "Your booking has been marked as completed."
            
            # Additional details for the completed booking email
            balance_payment = booking.total_amount - booking.booking_amount  # Calculate balance payment
            account_number = "1234567890"  # Example account number
            bank_name = "Example Bank"  # Example bank name
            ifsc_code = "EXAM1234567"  # Example IFSC code
            other_payment_methods = "Credit Card, PayPal"  # Example payment methods
            payment_deadline = timezone.now() + timezone.timedelta(days=7)  # Example deadline (7 days from now)
            
            # Create the completed booking email
            email_message = create_completed_booking_email(
                user, booking, balance_payment, account_number, bank_name, ifsc_code, other_payment_methods, payment_deadline
            )
            
            # Send email to user
            email = EmailMessage(
                subject=f"Booking Completed for {booking.service.name}",
                body=email_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            email.content_subtype = "html"  # Specify that the email content is HTML
            email.send(fail_silently=False)  # Send the email

        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action.'})
        
        booking.save()
        
        return JsonResponse({'status': 'success', 'message': f"Booking {action}d and email sent to user."})

    except VendorProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Vendor profile not found.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})
    

def create_completed_booking_email(user, booking, balance_payment, account_number, bank_name, ifsc_code, other_payment_methods, payment_deadline):
    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: #fff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            h1, h2, h3 {{
                color: #661c12;
            }}
            .summary {{
                margin: 20px 0;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: #f9f9f9;
            }}
            .footer {{
                margin-top: 20px;
                font-size: 0.9em;
                color: #777;
            }}
            .important-note {{
                font-weight: bold;
                color: #d9534f; /* Bootstrap danger color */
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Booking Completed</h1>
            <p>Dear {user.name},</p>

            <p>We hope this message finds you well!</p>

            <p>We are delighted to inform you that your booking with Dream Knot has been successfully completed. Thank you for choosing us to be a part of your special day. Below are the final details of your booking along with instructions for the remaining balance payment.</p>

            <div class="summary">
                <h2>Booking Summary:</h2>
                <ul>
                    <li><strong>Service:</strong> {booking.service.name}</li>
                    <li><strong>Event Date:</strong> {booking.event_date.strftime('%B %d, %Y')}</li>
                    <li><strong>Event Name:</strong> {booking.event_name}</li>
                    <li><strong>Event Address:</strong> {booking.event_address}</li>
                    <li><strong>Number of Days:</strong> {booking.num_days}</li>
                    <li><strong>Total Amount:</strong> ₹{booking.total_amount:,.2f}</li>
                    <li><strong>Paid Amount:</strong> ₹{booking.booking_amount:,.2f}</li>
                    <li><strong>Balance Payment Due:</strong> ₹{balance_payment:,.2f}</li>
                </ul>
                <p><strong>Additional Requirements:</strong> {booking.additional_requirements or 'None'}</p>
            </div>

            <h2>Payment Instructions:</h2>
            <p>To complete the balance payment, please choose one of the following options. Kindly ensure that the payment is made by the specified deadline to avoid any late fees or service disruptions.</p>
            <ul>
                <li><strong>Bank Transfer:</strong>
                    <ul>
                        <li><strong>Account Number:</strong> {account_number}</li>
                        <li><strong>Bank Name:</strong> {bank_name}</li>
                        <li><strong>IFSC Code:</strong> {ifsc_code}</li>
                    </ul>
                </li>
                <li><strong>Other Payment Methods:</strong> {other_payment_methods}</li>
                <li><strong>UPI Payment:</strong> If you prefer UPI, you can use our UPI ID or pay via direct cash.</li>
            </ul>

            <h2>Payment Deadline:</h2>
            <p>Please make the balance payment by {payment_deadline.strftime('%B %d, %Y')}. Late payments may incur additional fees as per our policy.</p>

            <p class="important-note">Important Note: After completing the payment, please retain the payment confirmation or receipt for your records. Should you have any questions regarding your booking or require assistance with the payment process, do not hesitate to reach out to our customer support team.</p>

            <p>Thank you once again for choosing Dream Knot! We look forward to helping you create more unforgettable memories in the future.</p>

            <p>Warm regards,<br>The Dream Knot Team</p>

            <div class="footer">
                <p><em>This email serves as a record of your booking completion and payment details.</em></p>
            </div>
        </div>
    </body>
    </html>
    """


def create_approved_booking_email(user, booking):
    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: #fff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            h1, h2 {{
                color: #28a745; /* Green for approved */
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Booking Approved</h1>
            <p>Dear {user.name},</p>
            <p>We are pleased to inform you that your booking has been approved!</p>
            <p>Thank you for choosing Dream Knot. We look forward to serving you on your special day.</p>
            <p>Booking Details:</p>
            <ul>
                <li><strong>Service:</strong> {booking.service.name}</li>
                <li><strong>Event Date:</strong> {booking.event_date.strftime('%B %d, %Y')}</li>
                <li><strong>Event Name:</strong> {booking.event_name}</li>
                <li><strong>Event Address:</strong> {booking.event_address}</li>
            </ul>
            <p>If you have any questions, feel free to reach out to our support team.</p>
            <p>Warm regards,<br>The Dream Knot Team</p>
        </div>
    </body>
    </html>
    """

def create_rejected_booking_email(user, booking):
    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: #fff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            h1, h2 {{
                color: #dc3545; /* Red for rejected */
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Booking Rejected</h1>
            <p>Dear {user.name},</p>
            <p>We regret to inform you that your booking has been rejected.</p>
            <p>We understand this may be disappointing, and we are here to assist you with any questions or concerns you may have.</p>
            <p>Booking Details:</p>
            <ul>
                <li><strong>Service:</strong> {booking.service.name}</li>
                <li><strong>Event Date:</strong> {booking.event_date.strftime('%B %d, %Y')}</li>
                <li><strong>Event Name:</strong> {booking.event_name}</li>
                <li><strong>Event Address:</strong> {booking.event_address}</li>
            </ul>
            <p>If you have any questions, please contact our support team.</p>
            <p>Warm regards,<br>The Dream Knot Team</p>
        </div>
    </body>
    </html>
    """




def dummy_refund_payment(booking):
    """
    Simulates a refund process for testing purposes.
    
    Args:
        booking: An instance of the Booking model containing payment details.
    
    Returns:
        bool: True if the refund is simulated successfully, False otherwise.
    """
    # Simulate some conditions for the refund
    if not booking.razorpay_payment_id:
        print("Refund failed: No payment ID found.")
        return False

    # Simulate refund eligibility check
    if not booking.is_refundable():
        print("Refund failed: Booking is not eligible for a refund.")
        return False

    # Simulate a successful refund process
    print(f"Simulating refund for booking ID: {booking.id}")
    print(f"Refund amount: ₹{booking.booking_amount}")

    # Here you can simulate additional logic, such as updating the booking status
    booking.book_status = 4  # Set status to 'Refunded'
    booking.refund_amount = booking.booking_amount  # Set the refund amount
    booking.save()  # Save the changes to the booking

    print(f"Refund successful for booking ID: {booking.id}")
    return True



def get_booking_details(request, booking_id):
    user_id = request.session.get('user_id')
    
    if not user_id:
        return JsonResponse({'status': 'error', 'message': 'You need to log in to perform this action.'})

    try:
        vendor_instance = VendorProfile.objects.get(user__id=user_id)
        booking = get_object_or_404(Booking, id=booking_id, service__vendor=vendor_instance)
        
        booking_details = {
            'id': booking.id,
            'service_name': booking.service.name,
            'user_name': booking.user.name,
            'user_email': booking.user.email,
            'user_phone': booking.user.phone,
            'event_date': booking.event_date.strftime('%Y-%m-%d'),
            'event_name': booking.event_name,
            'event_address': booking.event_address,
            'user_address': booking.user_address,
            'num_days': booking.num_days,
            'total_amount': str(booking.total_amount),
            'booking_amount': str(booking.booking_amount),
            'additional_requirements': booking.additional_requirements,
            'book_status': booking.get_book_status_display(),
            'reference_images': [image.image.url for image in booking.reference_images.all()],
            'booking_date': booking.booking_date.strftime('%Y-%m-%d %H:%M:%S'),
            'terms_agreed': booking.user_agreed_to_terms,
            'book_status': booking.book_status,  # Return the integer value
            
            'agreement_date': booking.user_agreement_date.strftime('%Y-%m-%d %H:%M:%S') if booking.user_agreement_date else None,
        }
        
        return JsonResponse({'status': 'success', 'booking': booking_details})

    except VendorProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Vendor profile not found.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def get_booking_slots(request, service_id):
    """API view to fetch booked and available slots for FullCalendar."""
    bookings = Booking.objects.filter(service_id=service_id)
    events = []

    # Status color mapping
    status_color_mapping = {
        0: ('Pending', 'orange'),  # Pending approval
        1: ('Confirmed', 'green'),  # Approved
        2: ('Completed', 'blue'),   # Completed
        3: ('Canceled', 'red'),     # Canceled
    }

    # Add booked slots to the events list
    for booking in bookings:
        event_status, color = status_color_mapping.get(booking.book_status, ('Unknown', 'gray'))
        events.append({
            'title': f'{event_status} - {booking.user.username}',  # Display username
            'start': booking.event_date.isoformat(),  # ISO format for date compatibility
            'color': color,
            'status': event_status
        })

    # Get available slots for the next 365 days
    today = now().date()
    future_dates = [today + timedelta(days=i) for i in range(365)]  # Next 365 days
    booked_dates = bookings.values_list('event_date', flat=True)  # List of already booked dates

    for date in future_dates:
        if date not in booked_dates:
            events.append({
                'title': 'Available',  # Mark as available
                'start': date.isoformat(),
                'color': 'lightgray',  # Use light gray for available slots
                'status': 'Available'
            })

    return JsonResponse(events, safe=False)

# views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Booking, Service, UserSignup
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
import json
# user view for booking calendar
# View to render the calendar and form page
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def booking_calendar_view(request, service_id):
    service = Service.objects.get(id=service_id)
    return render(request, 'dreamknot1/booking_calendar.html', {'service': service})

# API view to fetch booked and available slots for FullCalendar
from django.http import JsonResponse
from django.utils.timezone import now, timedelta

def get_booking_slots(request, service_id):
    # Fetch bookings for the given service
    bookings = Booking.objects.filter(service_id=service_id)
    events = []

    # Define status-to-color mapping
    status_color_mapping = {
        0: ('Pending', 'orange'),  # Vendor has not confirmed
        1: ('Confirmed', 'green'),  # Vendor confirmed the booking
        2: ('Completed', 'blue'),  # Booking is marked as completed
        3: ('Canceled', 'red'),  # Booking was canceled
    }

    # Add booked slots to the events list
    for booking in bookings:
        event_status, color = status_color_mapping.get(booking.book_status, ('Unknown', 'gray'))
        events.append({
            'title': f'{event_status}',
            'start': booking.event_date.isoformat(),  # ISO format for date compatibility
            'color': color,
            'status': event_status
        })

    # Optionally: Add available slots logic (e.g., next 30 days)
    # Assuming "available" means dates with no bookings in the next 30 days
    today = now().date()
    future_dates = [today + timedelta(days=i) for i in range(1095)]  # Next 30 days
    booked_dates = bookings.values_list('event_date', flat=True)  # List of already booked dates

    for date in future_dates:
        if date not in booked_dates:
            events.append({
                'title': 'Available',  # Mark as available
                'start': date.isoformat(),
                'color': 'lightgray',  # Use light gray for available slots
                'status': 'Available'
            })

    return JsonResponse(events, safe=False)


# View to handle booking submission
@csrf_exempt
def submit_booking(request, service_id):
    if request.method == 'POST':
        data = json.loads(request.body)
        event_date = data.get('event_date')

        # Create booking entry
        user = request.user
        service = Service.objects.get(id=service_id)
        Booking.objects.create(
            user=user,
            service=service,
            event_date=event_date,
            book_status=0  # Pending by default
        )
        return JsonResponse({'status': 'success', 'message': 'Booking submitted! Await vendor confirmation.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})






from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Booking, UserSignup
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings

# user view for booking details
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_booking_details(request):
    user_name = request.session.get('user_name')
    
    if not user_name:
        return redirect('login')
    
    user_signup = get_object_or_404(UserSignup, name=user_name)
    bookings = Booking.objects.filter(user=user_signup).select_related('service')
    
    today = timezone.now().date()

    
    
    for booking in bookings:
        booking.days_until_event = (booking.event_date - today).days
        booking.is_refundable = booking.days_until_event > 30

     # Determine if the service is a venue and set the venue city
        if booking.service.category == 'Venue':
            booking.is_venue = True
            booking.venue_city = booking.service.city  # Assuming the venue city is the address
        else:
            booking.is_venue = False
            booking.venue_city = booking.event_address  # Use event address for non-venue services

    
    if request.method == 'POST':
        booking_id = request.POST.get('booking_id')
        cancellation_reason = request.POST.get('cancellation_reason')
        
        booking = get_object_or_404(Booking, id=booking_id, user=user_signup)
        
        # Check if cancellation is within 30 days of the event
        days_until_event = (booking.event_date - today).days
        
        if days_until_event > 30:
            # Cancellation is more than 30 days before the event
            booking.book_status = 3
            booking.canceled_by_user = True
            booking.cancellation_reason = cancellation_reason
            booking.vendor_confirmed_at = None
            booking.save()
            
            # Send email to service provider
            send_mail(
                subject=f"Booking Cancellation: {booking.service.name}",
                message=f"""
                Dear Service Provider,

                A booking for your service has been canceled.

                Details:
                - Service: {booking.service.name}
                - Event Date: {booking.event_date}
                - Cancellation Reason: {cancellation_reason}

                The booking was canceled more than 30 days before the event, so a full refund will be processed.

                Best regards,
                Dream Knot Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[booking.service.vendor.user.email],
                fail_silently=False,
            )
            
            messages.success(request, "Your booking has been canceled successfully. A full refund will be processed.")
        else:
            # Cancellation is within 30 days of the event
            booking.book_status = 3
            booking.canceled_by_user = True
            booking.cancellation_reason = cancellation_reason
            booking.vendor_confirmed_at = None
            booking.save()
            
            # Send email to service provider
            send_mail(
                subject=f"Booking Cancellation: {booking.service.name}",
                message=f"""
                Dear Service Provider,

                A booking for your service has been canceled.

                Details:
                - Service: {booking.service.name}
                - Event Date: {booking.event_date}
                - Cancellation Reason: {cancellation_reason}

                The booking was canceled within 30 days of the event, so the booking amount is non-refundable.

                Best regards,
                Dream Knot Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[booking.service.vendor.user.email],
                fail_silently=False,
            )
            
            messages.warning(request, "Your booking has been canceled. However, as it's within 30 days of the event, the booking amount is non-refundable.")
        
        return redirect('user_booking_details')

    return render(request, 'dreamknot1/user_booking_details.html', {
        'bookings': bookings,
        'user_name': user_name,
        'today': today,
        'invoice_data': bookings  # Pass the bookings data for invoice generation

    })



from django.http import HttpResponse, HttpResponseRedirect
from django.template.loader import render_to_string
from django.shortcuts import get_object_or_404, redirect
from xhtml2pdf import pisa
from django.utils import timezone
from .models import UserSignup, Booking  # Adjust the import paths as necessary

def download_invoice(request, booking_id):
    # Ensure the user is authenticated via session
    user_name = request.session.get('user_name')
    if not user_name:
        return redirect('login')  # Redirect to login if the user is not authenticated

    # Fetch the user and booking details
    user_signup = get_object_or_404(UserSignup, name=user_name)
    booking = get_object_or_404(Booking, id=booking_id, user=user_signup)

    # Prepare the context for rendering the invoice template
    context = {
        'booking': booking,
        'user_name': user_name,
        'today': timezone.now().date(),
    }

    # Render the invoice template to an HTML string
    html_string = render_to_string('dreamknot1/invoice_template.html', context)

    # Set up the HTTP response for PDF generation
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="invoice_{booking_id}.pdf"'

    # Convert the HTML to a PDF document
    try:
        pisa_status = pisa.CreatePDF(html_string, dest=response)
        if pisa_status.err:  # Handle PDF generation errors
            return HttpResponse('Error generating PDF. Please try again later.')
    except Exception as e:
        return HttpResponse(f"An unexpected error occurred: {str(e)}")

    # Return the PDF as an attachment
    return response


from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from .models import Booking

# View to cancel a booking
def cancel_booking(request, booking_id):
    user_id = request.session.get('user_id')
    
    if not user_id:
        messages.error(request, "You must be logged in to cancel a booking.")
        return redirect('login')

    booking = get_object_or_404(Booking, id=booking_id, user__id=user_id)
    booking.delete()
    messages.success(request, "Your booking has been canceled successfully.")
    return redirect('user_booking_details')  # Redirect to the booking details page


# dreamproject/dreamknot1/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
from .models import Service, UserSignup, UserProfile, Booking, ReferenceImage
from decimal import Decimal
from django.views.decorators.cache import cache_control
import razorpay
from django.conf import settings
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def book_service(request, service_id):
    user_id = request.session.get('user_id')

    if not user_id:
        messages.error(request, "You must be logged in to book a service.")
        return redirect('login')

    try:
        service = get_object_or_404(Service, id=service_id)
        user = UserSignup.objects.get(id=user_id)
        user_name = user.name
    except UserSignup.DoesNotExist:
        messages.error(request, "User profile not found. Please log in again.")
        return redirect('login')
    except Service.DoesNotExist:
        messages.error(request, "The requested service does not exist.")
        return redirect('user_dashboard')
    
       # Retrieve the main image of the service
    service_image = service.main_image.url if service.main_image else None

    # Get category-specific details
    category_details = None
    if service.category == 'Venue':
        category_details = VenueService.objects.filter(service=service).first()
    elif service.category == 'Catering':
        category_details = CateringService.objects.filter(service=service).first()
    elif service.category == 'Photography':
        category_details = PhotographyService.objects.filter(service=service).first()
    elif service.category == 'MusicEntertainment':
        category_details = MusicEntertainmentService.objects.filter(service=service).first()
    elif service.category == 'MakeupHair':
        category_details = MakeupHairService.objects.filter(service=service).first()
    elif service.category == 'Rentals':
        category_details = RentalsService.objects.filter(service=service).first()
    elif service.category == 'MehendiArtist':
        category_details = MehendiArtistService.objects.filter(service=service).first()
    elif service.category == 'Decoration':
        category_details = DecorationService.objects.filter(service=service).first()


    if request.method == "POST":
        # Retrieve form data
        event_name = request.POST.get('event_name')
        event_date = request.POST.get('event_date')
        user_address = request.POST.get('user_address')
        num_days = int(request.POST.get('num_days', 1))
        additional_requirements = request.POST.get('additional_requirements')
        agreed_to_terms = request.POST.get('agreed_to_terms') == 'on'

        # Determine event address based on service category
        if service.category == 'Venue':
            event_address = service.city  # Assuming the venue city is the address
            venue_city = service.city  # Pass the venue city
        else:
            event_address = request.POST.get('event_address')  # Get from form input
            venue_city = None  # No venue city for non-venue services

        # Calculate total amount and booking amount
        total_amount = Decimal(service.price) * Decimal(num_days)  # Convert to Decimal
        booking_amount = total_amount * Decimal(0.5)  # 50% of total amount

        # Create new booking
        booking = Booking(
            user=user,
            service=service,
            event_name=event_name,
            event_date=event_date,
            event_address=event_address,
            user_address=user_address,
            num_days=num_days,
            total_amount=total_amount,
            booking_amount=booking_amount,
            additional_requirements=additional_requirements,
            user_agreed_to_terms=agreed_to_terms,
            user_agreement_date=timezone.now() if agreed_to_terms else None
        )
        booking.save()

        # Create Razorpay order
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        amount = int(booking_amount * 100)  # Amount in paise
        currency = 'INR'
        order_data = {
            'amount': amount,
            'currency': currency,
            'payment_capture': '1'  # Auto capture
        }
        order = client.order.create(data=order_data)
        razorpay_order_id = order['id']

        # Store the Razorpay order ID in the booking for later verification
        booking.razorpay_order_id = razorpay_order_id
        booking.save()

        remaining_balance = total_amount - booking_amount

        # Format amount for the template
        formatted_amount = amount  # Convert to paise

        # Redirect to the payment page with the order ID
        return render(request, 'dreamknot1/payment.html', {
            'razorpay_order_id': razorpay_order_id,
            'user':user,
            'amount': formatted_amount,
            'service': service,
            'user_name': user_name,
            'total_amount': total_amount,
            'booking_amount': booking_amount,
            'remaining_balance': remaining_balance,  # Pass remaining balance to the template
            'event_date': event_date,
            'event_address': event_address,
            'user_address': user_address,
            'num_days': num_days,
            'additional_requirements': additional_requirements,
            'venue_city': venue_city,  # Pass the venue city
            'service_image': service_image,  # Pass the service image
            'category_details': category_details,  # Pass category-specific details
            'booking': booking,  # Pass the booking object to the template

        })

    # For GET requests
    selected_date = request.GET.get('selected_date')

    # For GET requests, render the booking form
    context = {
        'service': service,
        'user': user,
        'terms_and_conditions': Booking().get_default_terms_and_conditions(),
        'user_name': user_name,
        'selected_date': selected_date,
        'is_venue': service.category == 'Venue',
        'venue_city': service.city if service.category == 'Venue' else None,
    }
    return render(request, 'dreamknot1/book_service.html', context)


# dreamproject/dreamknot1/views.py
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

@csrf_exempt
def payment_success(request):
    if request.method == 'GET':
        payment_id = request.GET.get('razorpay_payment_id')
        order_id = request.GET.get('razorpay_order_id')
        signature = request.GET.get('razorpay_signature')

        # Verify the payment signature
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        try:
            client.utility.verify_payment_signature({
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            })

            # Update the booking with payment details
            booking = Booking.objects.get(razorpay_order_id=order_id)
            booking.razorpay_payment_id = payment_id
            booking.razorpay_signature = signature
            booking.book_status = 1  # Mark as confirmed
            booking.save()


        
   # Send email to the user about booking confirmation
            subject = "Booking Payment Successful - Dream Knot"
            message = f"""
Dear {booking.user.name},

We are delighted to inform you that your payment has been successfully received, and your booking has been marked as confirmed. 

Booking Details:
- Booking ID: {booking.id}
- Payment ID: {payment_id}
- Event Date: {booking.event_date}
- Service: {booking.service.name}
- Vendor: {booking.service.vendor.user.name}
- Total Amount: {booking.total_amount}
- Booking Amount: {booking.booking_amount}
- Remaining Balance: {booking.total_amount-booking.booking_amount}

Please note that the service provider will review your booking and confirm the details shortly. You will receive a notification once the service provider confirms the booking.

Thank you for choosing Dream Knot for your special day.

Best regards,  
The Dream Knot Team
"""
            recipient_email = booking.user.email
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [recipient_email],
                fail_silently=False
            )



               # Redirect to bookings page with a success message
            messages.success(request, 'Payment verified successfully. Your booking is confirmed wait for vendor approval.')
            return redirect('user_booking_details')  # Replace 'bookings' with your actual bookings URL name


        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request.'})




# for filter in vendor booking details
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Booking, VendorProfile
from django.utils import timezone
from django.db.models import Q

def get_vendor_bookings(request):
    user_id = request.session.get('user_id')
    
    if not user_id:
        return JsonResponse({'status': 'error', 'message': 'You need to log in to perform this action.'})

    try:
        vendor_instance = VendorProfile.objects.get(user__id=user_id)
        
        # Get filter and sort parameters
        status_filter = request.GET.get('status', 'all')
        date_filter = request.GET.get('date', 'all')
        sort_by = request.GET.get('sort', 'date-asc')

        # Start with all bookings for this vendor
        bookings = Booking.objects.filter(service__vendor=vendor_instance)
         
        # Count bookings by status
        pending_count = bookings.filter(book_status=0).count()  # Pending
        confirmed_count = bookings.filter(book_status=1).count()  # Confirmed
        completed_count = bookings.filter(book_status=2).count()  # Completed
        canceled_count = bookings.filter(book_status=3).count()  # Canceled
        refunded_count = bookings.filter(book_status=4).count()  # Refunded

        # Apply status filter
        if status_filter != 'all':
            bookings = bookings.filter(book_status=status_filter.upper())

        # Apply date filter
        today = timezone.now().date()
        if date_filter == 'upcoming':
            bookings = bookings.filter(event_date__gte=today)
        elif date_filter == 'past':
            bookings = bookings.filter(event_date__lt=today)

        # Apply sorting
        if sort_by == 'date-asc':
            bookings = bookings.order_by('event_date')
        elif sort_by == 'date-desc':
            bookings = bookings.order_by('-event_date')
        elif sort_by == 'status':
            bookings = bookings.order_by('book_status', 'event_date')

        # Prepare the data for JSON response
        booking_data = []
        for booking in bookings:
            booking_data.append({
                'id': booking.id,
                'service_name': booking.service.name,
                'user_name': booking.user.name,
                'event_date': booking.event_date.strftime('%Y-%m-%d'),
                'book_status': booking.get_book_status_display(),
                'total_amount': str(booking.total_amount),
            })

        return JsonResponse({
            'status': 'success',
            'bookings': booking_data,
            'counts': {
                'pending': pending_count,
                'completed': completed_count,
                'refunded': refunded_count,
                'confirmed': confirmed_count,
    }
            
        })

    except VendorProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Vendor profile not found.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


# user view for check date availability
@require_POST
def check_date_availability(request, service_id):
    event_date = request.POST.get('event_date')
    service = get_object_or_404(Service, id=service_id)
    
    existing_booking = Booking.objects.filter(
        Q(service=service) &
        Q(event_date=event_date) &
        ~Q(book_status=3)  # Exclude cancelled bookings
    ).exists()
    
    return JsonResponse({'available': not existing_booking})

# user view for add to favorite

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_to_favorite(request, service_id):
    user_name = request.session.get('user_name', 'user')
    try:
        service = Service.objects.get(id=service_id)
        user = UserSignup.objects.get(name=user_name)
    except Service.DoesNotExist:
        return HttpResponse("Service not found.")
    except UserSignup.DoesNotExist:
        return HttpResponse("User not found.")

    # Add to favorites
    favorite, created = Favorite.objects.get_or_create(user=user, service=service)
    return redirect('user_dashboard')

# user view for favorite list
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def favorite_list(request):
    # Get the current logged-in user from the session (based on 'user_name')
    user_name = request.session.get('user_name')
    
    if not user_name:
        return HttpResponse("User is not logged in.")

    # Fetch the user object based on the username
    user = get_object_or_404(UserSignup, name=user_name)

    # Fetch all favorite services for this user
    favorites = Favorite.objects.filter(user=user).select_related('service')

    # Pass the favorites to the template for display
    return render(request, 'dreamknot1/favorite_list.html', {'favorites': favorites, 'user_name': user_name})

# user view for remove from favorite
from django.http import JsonResponse

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def remove_from_favorite(request, service_id):
    if request.method == "POST":
        user_name = request.session.get('user_name', 'user')
        try:
            service = Service.objects.get(id=service_id)
            user = UserSignup.objects.get(name=user_name)
        except Service.DoesNotExist:
            return JsonResponse({'error': "Service not found."}, status=404)
        except UserSignup.DoesNotExist:
            return JsonResponse({'error': "User not found."}, status=404)

        # Remove the service from favorites
        try:
            favorite = Favorite.objects.get(user=user, service=service)
            favorite.delete()
            return JsonResponse({'message': "Service removed from favorites successfully."}, status=200)
        except Favorite.DoesNotExist:
            return JsonResponse({'error': "Favorite not found."}, status=404)

    return JsonResponse({'error': "Invalid request method."}, status=400)


# user view for rate a service
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def rate_service(request, service_id):
    user_name = request.session.get('user_name', 'user')
    try:
        service = Service.objects.get(id=service_id)
        user = UserSignup.objects.get(name=user_name)
    except Service.DoesNotExist: 
        return HttpResponse("Service not found.")
    except UserSignup.DoesNotExist:
        return HttpResponse("User not found.")

    if request.method == "POST":
        rating_value = int(request.POST['rating'])
        rating, created = Rating.objects.update_or_create(user=user, service=service, defaults={'rating': rating_value})
        return redirect('user_dashboard')

    return render(request, 'dreamknot1/rate_service.html', {'service': service})



















from django.shortcuts import render, redirect
from django.shortcuts import render, get_object_or_404, redirect
from django.core.paginator import Paginator
# from django.contrib.auth.decorators import login_required
from .models import Service, UserSignup

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import UserSignup
from django.views.decorators.cache import cache_control


    

from django.db.models import Count
from django.shortcuts import render

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_dashboard(request):
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        try:
            admin = UserSignup.objects.get(id=user_id, role='admin', is_super=True)
            
            # Count and group services by category
            categories_count = Service.objects.values('category').annotate(count=Count('id'))
            services_by_category = Service.objects.all().order_by('category')
              # Preprocess categories for CSS class names
            for category in categories_count:
                category['css_class'] = category['category'].lower().replace(" ", "-")
            context = {
                'admin_name': admin.name,
                'categories_count': categories_count,
                'services_by_category': services_by_category,
            }
            return render(request, 'dreamknot1/admin_dashboard.html', context)
        except UserSignup.DoesNotExist:
            messages.error(request, "Admin user not found.")
            return redirect('login')
    else:
        messages.error(request, "You must be logged in as an admin to access this page.")
        return redirect('login')



from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.cache import cache_control
from django.db.models import Avg, Count, Q
from django.db import models
import json
from django.core.serializers.json import DjangoJSONEncoder
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_analytics(request):
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        try:
            admin = UserSignup.objects.get(id=user_id, role='admin', is_super=True)
            
            # Get overall statistics
            total_users = UserSignup.objects.filter(role='user').count()
            total_vendors = UserSignup.objects.filter(role='vendor').count()
            total_services = Service.objects.count()
            total_bookings = Booking.objects.count()
            
            # Get feedback statistics by category
            feedback_by_category = list(ServiceFeedback.objects.values(
                'service__category'
            ).annotate(
                avg_rating=Avg('rating'),
                total_feedback=Count('id')
            ).order_by('-avg_rating'))
            
            # Get top and bottom rated vendors
            top_vendors = VendorAnalytics.objects.select_related('vendor').order_by('-average_rating')[:5]
            bottom_vendors = VendorAnalytics.objects.select_related('vendor').order_by('average_rating')[:5]
            
            # Get feedback type analysis
            feedback_type_analysis = list(ServiceFeedback.objects.values(
                'feedback_type'
            ).annotate(
                avg_rating=Avg('rating'),
                total_count=Count('id')
            ).order_by('feedback_type'))
            
            # Get sentiment trends
            sentiment_trends = list(SentimentAnalysis.objects.values(
                'feedback__created_at__date'
            ).annotate(
                positive=Count('id', filter=Q(compound_score__gte=0.05)),
                negative=Count('id', filter=Q(compound_score__lte=-0.05)),
                neutral=Count('id', filter=Q(compound_score__gt=-0.05, compound_score__lt=0.05))
            ).order_by('-feedback__created_at__date')[:30])
            
            # Get most common feedback topics
            all_topics = {}
            for analytics in VendorAnalytics.objects.all():
                if analytics.common_feedback_topics:  # Check if not None
                    for topic, freq in analytics.common_feedback_topics.items():
                        all_topics[topic] = all_topics.get(topic, 0) + freq
            
            top_topics = dict(sorted(all_topics.items(), key=lambda x: x[1], reverse=True)[:20])
            
            context = {
                'admin_name': admin.name,
                'total_users': total_users,
                'total_vendors': total_vendors,
                'total_services': total_services,
                'total_bookings': total_bookings,
                'feedback_by_category': json.dumps(feedback_by_category, cls=DjangoJSONEncoder),
                'top_vendors': top_vendors,
                'bottom_vendors': bottom_vendors,
                'feedback_type_analysis': json.dumps(feedback_type_analysis, cls=DjangoJSONEncoder),
                'sentiment_trends': json.dumps(sentiment_trends, cls=DjangoJSONEncoder),
                'top_topics': json.dumps(top_topics)
            }
            
            return render(request, 'dreamknot1/admin_analytics.html', context)
            
        except UserSignup.DoesNotExist:
            messages.error(request, "Admin user not found.")
            return redirect('login')
    else:
        messages.error(request, "You must be logged in as an admin to access this page.")
        return redirect('login')

# admin view for base
def base(request):
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        try:
            admin = UserSignup.objects.get(id=user_id, role='admin', is_super=True)
            context = {
                'admin_name': admin.name,
                # Add any other context data you want to pass to the template
            }
            return render(request, 'dreamknot1/admin_dashboard.html', context)
        except UserSignup.DoesNotExist:
            messages.error(request, "Admin user not found.")
            return redirect('login')
    else:
        messages.error(request, "You must be logged in as an admin to access this page.")
        return redirect('login')

# admin view for view users
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_users(request):
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        try:
            admin = UserSignup.objects.get(id=user_id, role='admin', is_super=True)
            role_filter = request.GET.get('role', 'user')

            if role_filter == 'vendor':
                users = UserSignup.objects.filter(role='vendor')
            else:
                users = UserSignup.objects.filter(role='user')
            
            user_count = UserSignup.objects.filter(role='user').count()
            vendor_count = UserSignup.objects.filter(role='vendor').count()


            context = {
                'users': users,
                'role_filter': role_filter,
                'admin_name': admin.name,
                'user_count': user_count,
        'vendor_count': vendor_count,
            }
            return render(request, 'dreamknot1/view_users.html', context)
        except UserSignup.DoesNotExist:
            messages.error(request, "Admin user not found.")
            return redirect('login')
    else:
        messages.error(request, "You must be logged in as an admin to access this page.")
        return redirect('login')

from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from .models import UserSignup

# admin view for toggle user status
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def toggle_user_status(request, user_id):
    # Fetch the user by ID
    user = get_object_or_404(UserSignup, id=user_id)
    
    # Toggle the user's status
    user.status = not user.status
    user.save()
    
    # Send email notification based on the user's new status
    subject = f"Your account has been {'activated' if user.status else 'deactivated'}"
    message = f"Dear {user.name},\n\nYour account has been {'activated' if user.status else 'deactivated'} by the admin. You can {'now access' if user.status else 'no longer access'} your account.\n\nBest regards,\nDream Knot Team"
    recipient_email = user.email

    # Send the email
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,  # This should be your configured email, e.g., dreamknot0@gmail.com
        [recipient_email],
        fail_silently=False,
    )
    
    # Add a success message
    if user.status:
        messages.success(request, f"{user.name} has been activated and an email has been sent.")
    else:
        messages.success(request, f"{user.name} has been deactivated and an email has been sent.")
    
    # Redirect to the same page or the users list
    return redirect('view_users')





# View Venues (restricted to admin users)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_venues(request):
    if request.user.role == 'admin':
        venues = Service.objects.all()
        paginator = Paginator(venues, 10)  # Show 10 venues per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'venues': page_obj,  # Passing paginated venues
            'is_paginated': True if paginator.num_pages > 1 else False,
            'page_obj': page_obj
        }
        return render(request, 'view_venues.html', context)
    else:
        return redirect('login')

# Edit Venue (restricted to admin users)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_venue(request, id):
    if request.user.role == 'admin':
        venue = get_object_or_404(Service, id=id)
        if request.method == 'POST':
            venue.name = request.POST['name']
            venue.location = request.POST['location']
            venue.capacity = request.POST['capacity']
            venue.price = request.POST['price']
            venue.availability = request.POST.get('availability', False)
            venue.save()
            return redirect('view_venues')
        return render(request, 'edit_venue.html', {'venue': venue})
    else:
        return redirect('login')

# Delete Venue (restricted to admin users)

def delete_venue(request, id):
    if request.user.role == 'admin':
        venue = get_object_or_404(Service, id=id)
        venue.delete()
        return redirect('view_venues')
    else:
        return redirect('login')







from django.shortcuts import render, redirect, get_object_or_404
from .models import WeddingTask
from django.contrib import messages
from django.views.decorators.cache import cache_control

# admin view for manage predefined tasks- add, edit, delete
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def manage_predefined_tasks(request):
    # Check if the user is logged in as an admin
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        if request.method == 'POST':
            action = request.POST.get('action')
            
            if action == 'add':
                description = request.POST.get('description')
                task_month = request.POST.get('task_month')
                
                if description and task_month:
                    WeddingTask.objects.create(
                        description=description,
                        task_month=task_month,
                        is_predefined=True,
                        user=None
                    )
                    messages.success(request, "Predefined task added successfully.")
                else:
                    messages.error(request, "Please provide both description and task month.")
            
            elif action == 'edit':
                task_id = request.POST.get('task_id')
                description = request.POST.get('description')
                task_month = request.POST.get('task_month')
                
                if task_id and description and task_month:
                    task = get_object_or_404(WeddingTask, id=task_id, is_predefined=True, user=None)
                    task.description = description
                    task.task_month = task_month
                    task.save()
                    messages.success(request, "Predefined task updated successfully.")
                else:
                    messages.error(request, "Invalid edit request.")
            
            elif action == 'delete':
                task_id = request.POST.get('task_id')
                
                if task_id:
                    task = get_object_or_404(WeddingTask, id=task_id, is_predefined=True, user=None)
                    task.delete()
                    messages.success(request, "Predefined task deleted successfully.")
                else:
                    messages.error(request, "Invalid delete request.")
        
        predefined_tasks = WeddingTask.objects.filter(is_predefined=True, user=None)
        context = {
            'task_month_choices': WeddingTask.TASK_MONTH_CHOICES,
            'tasks': predefined_tasks,
            'admin_name': UserSignup.objects.get(id=user_id).name,  # Pass admin name for context
        }
        return render(request, 'dreamknot1/manage_predefined_tasks.html', context)
    else:
        messages.error(request, "You must be logged in as an admin to manage predefined tasks.")
        return redirect('login')

# admin view for list predefined tasks

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def list_predefined_tasks(request):
    # Check if the user is logged in as an admin
    user_id = request.session.get('user_id')
    user_role = request.session.get('user_role')
    
    if user_id and user_role == 'admin':
        predefined_tasks = WeddingTask.objects.filter(is_predefined=True, user=None)
        context = {
            'tasks': predefined_tasks,
            'admin_name': UserSignup.objects.get(id=user_id).name,  # Pass admin name for context
        }
        return render(request, 'dreamknot1/list_predefined_tasks.html', context)
    else:
        messages.error(request, "You must be logged in as an admin to view predefined tasks.")
        return redirect('login')

from django.shortcuts import redirect
from django.contrib import messages
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import AuthAlreadyAssociated, AuthException

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def google_login_callback(request):
    try:
        error_message = request.session.get('error_message')
        if error_message:
            messages.error(request, error_message)
            del request.session['error_message']
            return redirect('login')

        # Check if user is already authenticated via social
        if request.session.get('is_social'):
            user_id = request.session.get('user_id')
            if user_id:
                try:
                    user = UserSignup.objects.get(id=user_id)
                    if user.is_social_user:
                        messages.success(request, "Successfully logged in with Google!")
                        return redirect('user_home')
                except UserSignup.DoesNotExist:
                    pass

        # If we get here, something went wrong
        messages.error(request, "Something went wrong during Google login.")
        return redirect('login')

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('login')
    
import requests
from bs4 import BeautifulSoup
from django.core.cache import cache
from django.shortcuts import render
from datetime import datetime
import random
from django.conf import settings

def extract_image_from_content(content):
    try:
        soup = BeautifulSoup(content, 'lxml')
        img = soup.find('img')
        return img['src'] if img else None
    except Exception as e:
        print(f"Error extracting image: {e}")
        return None
    

def fetch_rss_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'xml')
            items = soup.find_all('item')
            if not items:
                print(f"No items found in feed: {url}")
            return items if items else []
        else:
            print(f"Failed to fetch feed: {url} with status code: {response.status_code}")
    except Exception as e:
        print(f"RSS Feed error: {e} for URL: {url}")
        if response is not None:
            print(f"Response content: {response.content}")
    return []

def fetch_wedding_blogs(search_query=None):
    blogs = []
    
    # 1. Wedding Blog RSS Feeds
    rss_feeds = [
        {
            'url': 'https://www.confettidaydreams.com/feed/',
            'source': 'Confetti Daydreams'
        },
        {
            'url': 'https://www.weddingbee.com/feed/',
            'source': 'Wedding Bee'
        },
        {
            'url': 'https://www.stylemepretty.com/feed/',
            'source': 'Style Me Pretty'
        },
        {
            'url': 'https://greenweddingshoes.com/feed/',
            'source': 'Green Wedding Shoes'
        },
        {
            'url': 'https://ruffledblog.com/feed/',
            'source': 'Ruffled Blog'
        },
        {
            'url': 'https://bridalmusings.com/feed/',
            'source': 'Bridal Musings'
        },
        {
            'url': 'https://www.loveandlavender.com/feed/',
            'source': 'Love and Lavender'
        },
        {
            'url': 'https://offbeatbride.com/feed/',
            'source': 'Offbeat Bride'
        }
    ]

    for feed in rss_feeds:
        try:
            items = fetch_rss_content(feed['url'])
            for item in items[:15]:
                try:
                    title = item.find('title').text if item.find('title') else 'Wedding Article'
                    content = item.find('description').text[:200] if item.find('description') else ''
                    # Filter based on search query
                    if search_query and (search_query.lower() not in title.lower() and search_query.lower() not in content.lower()):
                        continue  # Skip if search query is not in title or content
                    blogs.append({
                        'type': 'article',
                        'title': title,
                        'content': content,
                        'image_url': extract_image_from_content(item.find('description').text) if item.find('description') else None,
                        'author': feed['source'],
                        'date': item.find('pubDate').text if item.find('pubDate') else datetime.now().strftime('%B %d, %Y'),
                        'category': 'Wedding_Tips',
                        'link': item.find('link').text if item.find('link') else '#',
                        'likes': random.randint(50, 200),
                        'comments': random.randint(5, 30)
                    })
                except Exception as e:
                    print(f"Error processing RSS item: {e}")
                    continue
        except Exception as e:
            print(f"Error processing feed {feed['url']}: {e}")
            continue

    # 2. Fetch images from Unsplash using the search query
    fetch_unsplash_images(blogs, search_query)

    # 3. Pexels Wedding Photos API using the search query
    try:
        headers = {'Authorization': settings.PEXELS_API_KEY}
        response = requests.get(
            f'https://api.pexels.com/v1/search?query={search_query or "wedding"}&per_page=25',
            headers=headers
        )
        if response.status_code == 200:
            photos = response.json().get('photos', [])
            for photo in photos:
                blogs.append({
                    'type': 'inspiration',
                    'title': 'Wedding Inspiration',
                    'image_url': photo['src']['large'],
                    'category': 'Wedding_Inspiration',
                    'photographer': photo['photographer'],
                    'link': photo['url'],
                    'likes': random.randint(100, 500),
                    'saves': random.randint(50, 200)
                })
    except Exception as e:
        print(f"Pexels API error: {e}")

    # 4. YouTube Wedding Videos using the search query
    try:
        youtube_url = "https://www.googleapis.com/youtube/v3/search"
        params = {
            'part': 'snippet',
            'q': search_query or 'wedding ideas',  # Use the search query
            'type': 'video',
            'maxResults': 15,
            'key': settings.YOUTUBE_API_KEY,
            'relevanceLanguage': 'en',
            'videoDuration': 'medium'
        }
        response = requests.get(youtube_url, params=params)
        if response.status_code == 200:
            videos = response.json().get('items', [])
            for video in videos:
                blogs.append({
                    'type': 'video',
                    'title': video['snippet']['title'],
                    'content': video['snippet']['description'][:150],
                    'thumbnail_url': video['snippet']['thumbnails']['high']['url'],
                    'video_id': video['id']['videoId'],
                    'category': 'Wedding_Videos',
                    'author': video['snippet']['channelTitle'],
                    'date': datetime.strptime(
                        video['snippet']['publishedAt'], 
                        '%Y-%m-%dT%H:%M:%SZ'
                    ).strftime('%B %d, %Y'),
                    'views': random.randint(1000, 50000),
                    'link': f"https://www.youtube.com/watch?v={video['id']['videoId']}"
                })
    except Exception as e:
        print(f"YouTube API error: {e}")

    # Add fallback content if no content was fetched
    if not blogs:
        blogs.append({
            'type': 'article',
            'title': 'Wedding Planning Tips',
            'content': 'Discover the latest trends in wedding planning and decoration.',
            'image_url': '/static/images/categories/placeholder.jpg',
            'author': 'Wedding Blog',
            'date': datetime.now().strftime('%B %d, %Y'),
            'category': 'Wedding_Tips',
            'link': '#',
            'likes': random.randint(50, 200),
            'comments': random.randint(5, 30)
        })

    return blogs
def wedding_blogs_view(request):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view wedding blogs.")
        return redirect('login')  # Redirect to the login page

    # Get the search query from the request
    search_query = request.GET.get('search')

    # Get blogs from cache or fetch new ones
    cached_blogs = cache.get(f'wedding_blogs_{search_query}')  # Cache based on search query
    if not cached_blogs:
        cached_blogs = fetch_wedding_blogs(search_query)  # Pass the search query
        cache.set(f'wedding_blogs_{search_query}', cached_blogs, 3600)

    # Filter by category
    category = request.GET.get('category')
    if category and category.lower() != 'all':
        blogs = [blog for blog in cached_blogs if blog['category'] == category]
    else:
        blogs = cached_blogs

    # Search functionality
    if search_query:
        blogs = [
            blog for blog in blogs 
            if search_query.lower() in blog['title'].lower() 
            or search_query.lower() in blog.get('content', '').lower()
        ]

    context = {
        'blogs': blogs,
        'categories': [
            ('All', 'all'),
            ('Wedding_Tips', 'Tips & Ideas'),
            ('Wedding_Inspiration', 'Inspiration'),
            ('Wedding_Videos', 'Videos')
        ],
        'current_category': category or 'All',
        'search_query': search_query
    }
    
    return render(request, 'dreamknot1/wedding_blogs.html', context)
def fetch_unsplash_images(blogs, search_query=None):
    try:
        headers = {'Authorization': f'Client-ID {settings.API_SETTINGS["UNSPLASH"]["ACCESS_KEY"]}'}
        response = requests.get(
            'https://api.unsplash.com/search/photos',
            headers=headers,
            params={'query': search_query or 'wedding', 'per_page': settings.API_SETTINGS['UNSPLASH']['PER_PAGE']}
        )
        if response.status_code == 200:
            photos = response.json().get('results', [])
            for photo in photos:
                blogs.append({
                    'type': 'inspiration',
                    'title': 'Wedding Inspiration',
                    'image_url': photo['urls']['regular'],  # Use the appropriate size
                    'category': 'Wedding_Inspiration',
                    'photographer': photo['user']['name'],
                    'link': photo['links']['html'],
                    'likes': random.randint(100, 500),
                    'saves': random.randint(50, 200)
                })
        else:
            print(f"Error fetching from Unsplash: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Unsplash API error: {e}")


# dreamproject/dreamknot1/views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging
from openai import OpenAI  # Import the OpenAI client
from django.conf import settings
import os
# Set your OpenAI API key
api_key = os.getenv('OPENAI_API_KEY')  # Renamed for clarity since this appears to be an OpenAI key# Your DeepAI API key

# Configure logging
logger = logging.getLogger(__name__)

# Initialize the OpenAI client
client = OpenAI(api_key=api_key)

@csrf_exempt  # Disable CSRF for this view (use with caution)
def chatbot_response(request):
    if request.method == 'POST':
        user_message = request.POST.get('message')

        if not user_message:
            return JsonResponse({'error': 'No message provided'}, status=400)

        try:
            # Call the AI service to get a response
            completion = client.chat.completions.create(
                model="gpt-4o-mini",  # Use the appropriate model
                messages=[{"role": "user", "content": user_message}]
            )

            # Log the full response for debugging
            logger.info(f"OpenAI response: {completion}")

            # Check if choices are available
            if not completion.choices:
                return JsonResponse({'error': 'No response from AI'}, status=500)

            # Extract the AI's response using dot notation
            ai_message = completion.choices[0].message.content  # Use dot notation here
            return JsonResponse({'response': ai_message})

        except Exception as e:
            logger.error(f"Error fetching response from OpenAI: {e}")
            return JsonResponse({'error': 'Failed to get response from AI'}, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)

import os  # Ensure this import is present
import time  # Ensure this import is present
import base64  # Ensure this import is present
import requests  # Ensure this import is present
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging
import nltk
from collections import Counter
from textblob import TextBlob
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from django.utils.html import strip_tags  # Add this import


# Replace with your actual Hugging Face API key
HUGGING_FACE_API_KEY = os.getenv('HUGGING_FACE_API_KEY')

# Configure logging
logger = logging.getLogger(__name__)

@csrf_exempt
def generate_image(request):
    if request.method == 'POST':
        user_description = request.POST.get('description')

        if not user_description:
            return JsonResponse({'error': 'No description provided'}, status=400)

        try:
            logger.info(f"Generating image with description: {user_description}")

            # API request headers
            headers = {
                'Authorization': f'Bearer {HUGGING_FACE_API_KEY}',
                'Content-Type': 'application/json'
            }

            # Payload with user input and optional parameters
            payload = {
                'text_prompts': [{'text': user_description}],
                'cfg_scale': 7.5,  # Prompt adherence (lower = more creative)
                'width': 1024,  # Allowed width
                'height': 1024,  # Allowed height
                'samples': 1  # Number of images to generate
            }

            # Make API request
            response = requests.post(
                'https://api.stability.ai/v1/generation/stable-diffusion-xl-1024-v1-0/text-to-image',
                headers=headers,
                json=payload
            )

            logger.info(f"Response status code: {response.status_code}")

            # Handle API response
            if response.status_code == 200:
                response_data = response.json()

                if 'artifacts' in response_data and response_data['artifacts']:
                    # Extract base64 image data
                    image_data = response_data['artifacts'][0].get('base64')
                    if image_data:
                        # Ensure the directory exists
                        os.makedirs('media/generated_images', exist_ok=True)  # Create directory if it doesn't exist
                        
                        # Save the image to a file
                        image_file_path = f'media/generated_images/image_{int(time.time())}.png'
                        with open(image_file_path, 'wb') as image_file:
                            image_file.write(base64.b64decode(image_data))
                        
                        # Return the URL of the saved image
                        return JsonResponse({'image_url': f'/{image_file_path}'})
                else:
                    logger.error("No artifacts found in response.")
                    return JsonResponse({'error': 'No images generated'}, status=500)
            else:
                logger.error(f"API returned an error: {response.text}")
                return JsonResponse({'error': 'Failed to generate image'}, status=response.status_code)

        except Exception as e:
            logger.error(f"Error generating image: {e}")
            return JsonResponse({'error': 'An error occurred'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)
from django.core.files.storage import FileSystemStorage

@csrf_exempt
def search_by_image(request):
    if request.method == 'POST' and request.FILES['image']:
        uploaded_file = request.FILES['image']
        fs = FileSystemStorage()
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_url = fs.url(filename)

        try:
            # Call the Google Vision API (replace with actual API endpoint)
            with open(file_url, 'rb') as image_file:
                image_content = image_file.read()

            response = requests.post(
                'https://vision.googleapis.com/v1/images:annotate?key=YOUR_GOOGLE_VISION_API_KEY',  # Replace with your API key
                json={
                    'requests': [{
                        'image': {
                            'content': image_content.decode('ISO-8859-1')  # Encode the image content
                        },
                        'features': [{
                            'type': 'LABEL_DETECTION',
                            'maxResults': 5
                        }]
                    }]
                }
            )

            if response.status_code == 200:
                labels = response.json().get('responses')[0].get('labelAnnotations', [])
                return JsonResponse({'labels': labels})
            else:
                return JsonResponse({'error': 'Failed to analyze image'}, status=response.status_code)

        except Exception as e:
            logger.error(f"Error searching by image: {e}")
            return JsonResponse({'error': 'Failed to analyze image'}, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)
# Example Django view for image upload
from django.http import JsonResponse
from django.core.files.storage import FileSystemStorage

def upload_image(request):
    if request.method == 'POST' and request.FILES.get('image'):
        image = request.FILES['image']
        fs = FileSystemStorage()
        filename = fs.save(image.name, image)
        image_url = fs.url(filename)  # Generate the URL for the uploaded image
        return JsonResponse({'success': True, 'image_url': image_url})
    return JsonResponse({'success': False, 'message': 'No image uploaded'})




from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from textblob import TextBlob
from collections import Counter
import json
from .models import ServiceFeedback, SentimentAnalysis, VendorAnalytics
from django.db.models import Avg, Count
from django.core.mail import send_mail
from django.template.loader import render_to_string


def submit_service_feedback(request, booking_id):
    print("Starting submit_service_feedback")  # Debug log
    user_id = request.session.get('user_id')
    print(f"User ID from session: {user_id}")  # Debug log
    
    if not user_id:
        print("No user_id in session, redirecting to login")  # Debug log
        return redirect('login')
    
    try:
        booking = get_object_or_404(Booking, id=booking_id, user_id=user_id)
        print(f"Found booking: {booking.id}")  # Debug log
    except Exception as e:
        print(f"Error finding booking: {str(e)}")  # Debug log
        messages.error(request, 'Invalid booking.')
        return redirect('user_bookings')
    
    if request.method == 'POST':
        try:
            print("POST data:", request.POST)  # Debug log
            feedback_types = ['service_quality', 'communication', 'value_for_money', 'professionalism', 'overall']
            
            for feedback_type in feedback_types:
                rating = request.POST.get(f'rating_{feedback_type}')
                text_feedback = request.POST.get(f'feedback_{feedback_type}')
                print(f"Processing {feedback_type}: rating={rating}, text={text_feedback}")  # Debug log
                
                if rating and text_feedback:
                    try:
                        # Try to get existing feedback
                        feedback, created = ServiceFeedback.objects.get_or_create(
                            booking=booking,
                            feedback_type=feedback_type,
                            defaults={
                                'service': booking.service,
                                'user_id': user_id,
                                'rating': rating,
                                'text_feedback': text_feedback
                            }
                        )
                        
                        if not created:
                            # Update existing feedback
                            feedback.rating = rating
                            feedback.text_feedback = text_feedback
                            feedback.save()
                            print(f"Updated existing feedback for {feedback_type}")  # Debug log
                        else:
                            print(f"Created new feedback for {feedback_type}")  # Debug log
                        
                        # Analyze sentiment and update vendor analytics
                        analyze_sentiment(feedback)
                        update_vendor_analytics(booking.service.vendor)
                        
                        # Notify vendor about new feedback
                        if created:
                            notify_vendor_new_feedback(booking.service.vendor, booking)
                            
                    except Exception as e:
                        print(f"Error processing feedback for {feedback_type}: {str(e)}")  # Debug log
                        raise e
            
            messages.success(request, 'Thank you for your feedback!')
            return redirect('user_booking_details')
            
        except Exception as e:
            print(f"Error in feedback submission: {str(e)}")  # Debug log
            messages.error(request, f'Error submitting feedback: {str(e)}')
            return redirect('user_booking_details')
    
    # For GET request, display the feedback form
    feedback_types = ['service_quality', 'communication', 'value_for_money', 'professionalism', 'overall']
    context = {
        'booking': booking,
        'feedback_types': feedback_types
    }
    return render(request, 'feedback/feedback_form.html', context)

def analyze_sentiment(feedback):
    try:
        print(f"\nAnalyzing feedback text: {feedback.text_feedback}")
        
        # Initialize VADER sentiment analyzer
        analyzer = SentimentIntensityAnalyzer()
        
        # Get sentiment scores from VADER (this doesn't require NLTK resources)
        vader_scores = analyzer.polarity_scores(feedback.text_feedback)
        #print(f"VADER scores: {vader_scores}")
        
        # Initialize empty keyword dict in case TextBlob fails
        keyword_dict = {}
        
        try:
            # Try to import and download required NLTK data
            import nltk
            try:
                nltk.data.find('tokenizers/punkt')
                nltk.data.find('taggers/averaged_perceptron_tagger')
            except LookupError:
                print("Downloading required NLTK data...")
                nltk.download('punkt')
                nltk.download('averaged_perceptron_tagger')
                nltk.download('brown')  # Additional corpus that might be needed
                nltk.download('universal_tagset')  # Additional tagset that might be needed
            
            # Try TextBlob analysis
            blob = TextBlob(feedback.text_feedback)
            print(f"TextBlob tags: {blob.tags}")
            
            # Extract keywords (nouns and adjectives)
            keywords = []
            for word, tag in blob.tags:
                if tag.startswith(('JJ', 'NN')):  # Adjectives and Nouns
                    clean_word = word.lower().strip()
                    if len(clean_word) > 2:  # Only include words longer than 2 characters
                        keywords.append(clean_word)
            
            print(f"Extracted keywords: {keywords}")
            
            # Count keyword frequencies
            keyword_freq = Counter(keywords).most_common(10)
            keyword_dict = dict(keyword_freq)
            print(f"Keyword frequencies: {keyword_dict}")
            
        except Exception as e:
            print(f"TextBlob processing error: {str(e)}")
            # Try downloading corpora directly
            try:
                import subprocess
                print("Attempting to download TextBlob corpora...")
                subprocess.run(['python', '-m', 'textblob.download_corpora'])
            except Exception as e:
                print(f"Error downloading corpora: {str(e)}")
            keyword_dict = {}
        
        # Create or update sentiment analysis (this will work even if TextBlob fails)
        sentiment, created = SentimentAnalysis.objects.update_or_create(
            feedback=feedback,
            defaults={
                'compound_score': vader_scores['compound'],
                'positive_score': vader_scores['pos'],
                'negative_score': vader_scores['neg'],
                'neutral_score': vader_scores['neu'],
                'keywords': keyword_dict
            }
        )
        
        print(f"Saved sentiment analysis - keywords: {sentiment.keywords}")
        
        # Update vendor analytics
        update_vendor_analytics(feedback.service.vendor)
        
        return sentiment
        
    except Exception as e:
        print(f"Error in analyze_sentiment: {str(e)}")
        # Create a basic sentiment analysis record even if everything fails
        sentiment, created = SentimentAnalysis.objects.update_or_create(
            feedback=feedback,
            defaults={
                'compound_score': 0.0,
                'positive_score': 0.0,
                'negative_score': 0.0,
                'neutral_score': 1.0,
                'keywords': {}
            }
        )
        return sentiment
        
def update_vendor_analytics(vendor):
    
    feedbacks = ServiceFeedback.objects.filter(
        service__vendor=vendor,
        status=True
    ).select_related('sentiment')
    
    # Calculate average ratings and total reviews
    avg_rating = feedbacks.aggregate(Avg('rating'))['rating__avg'] or 0.0
    total_reviews = feedbacks.count()
    
    # Initialize counters
    sentiment_data = {'positive': 0, 'negative': 0, 'neutral': 0}
    all_keywords = {}
    
    # Process each feedback
    for feedback in feedbacks:
        try:
            sentiment = feedback.sentiment
            # Update sentiment counters
            if sentiment.compound_score >= 0.05:
                sentiment_data['positive'] += 1
            elif sentiment.compound_score <= -0.05:
                sentiment_data['negative'] += 1
            else:
                sentiment_data['neutral'] += 1
            
            # Update keyword frequencies
            if sentiment.keywords:
                for keyword, freq in sentiment.keywords.items():
                    freq = int(freq) if isinstance(freq, (int, float)) else 1
                    all_keywords[keyword] = all_keywords.get(keyword, 0) + freq
        except (SentimentAnalysis.DoesNotExist, AttributeError):
            continue
    
    # Format common topics for word cloud
    if all_keywords:
        # Get top 20 keywords
        sorted_keywords = sorted(all_keywords.items(), key=lambda x: x[1], reverse=True)[:20]
        max_freq = sorted_keywords[0][1]
        min_freq = sorted_keywords[-1][1]
        
        # Normalize frequencies to a range suitable for d3.layout.cloud (10-100)
        if max_freq != min_freq:
            common_topics = {
                word: int(10 + ((freq - min_freq) * 90) / (max_freq - min_freq))
                for word, freq in sorted_keywords
            }
        else:
            common_topics = {word: 50 for word, _ in sorted_keywords}
    else:
        common_topics = {}
    
    # Update analytics
    VendorAnalytics.objects.update_or_create(
        vendor=vendor,
        defaults={
            'average_rating': avg_rating,
            'total_reviews': total_reviews,
            'sentiment_summary': sentiment_data,
            'common_feedback_topics': common_topics
        }
    )
def notify_vendor_new_feedback(vendor, booking):
    subject = 'New Feedback Received'
    context = {
        'vendor_name': vendor.company_name,
        'service_name': booking.service.name,
        'booking_date': booking.booking_date
    }
    
    html_message = render_to_string('emails/new_feedback_notification.html', context)
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject,
        plain_message,
        'noreply@dreamknot.com',
        [vendor.user.email],
        html_message=html_message,
        fail_silently=True
    )


def view_vendor_analytics(request, vendor_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    
    vendor = get_object_or_404(VendorProfile, id=vendor_id, user_id=user_id)
    
    try:
        analytics = vendor.analytics
    except VendorAnalytics.DoesNotExist:
        analytics = VendorAnalytics.objects.create(
            vendor=vendor,
            sentiment_summary={'positive': 0, 'neutral': 0, 'negative': 0},
            common_feedback_topics={}
        )
    
    # Get recent feedbacks
    recent_feedbacks = ServiceFeedback.objects.filter(
        service__vendor=vendor
    ).select_related('sentiment').order_by('-created_at')[:5]
    
     # Get negative feedbacks for areas of improvement
    negative_feedbacks = ServiceFeedback.objects.filter(
        service__vendor=vendor,
        sentiment__compound_score__lt=-0.05  # Adjust threshold as needed
    ).select_related('sentiment').order_by('-created_at')
    
       # Get positive feedbacks
    positive_feedbacks = ServiceFeedback.objects.filter(
        service__vendor=vendor,
        sentiment__compound_score__gt=0.05
    ).select_related('sentiment').order_by('-created_at')


    # Get feedback trends over time
    days = request.GET.get('days', '30')  # Default to 30 days
    try:
        days = int(days)
    except ValueError:
        days = 30
    
    from_date = timezone.now() - timezone.timedelta(days=days)
    
    feedback_trends = ServiceFeedback.objects.filter(
        service__vendor=vendor,
        created_at__gte=from_date
    ).values('created_at__date').annotate(
        avg_rating=Avg('rating'),
        count=Count('id')
    ).order_by('created_at__date')
    
    # Prepare data for charts
    import json
    feedback_trends_dates = json.dumps([trend['created_at__date'].strftime('%Y-%m-%d') for trend in feedback_trends])
    feedback_trends_ratings = json.dumps([float(trend['avg_rating']) if trend['avg_rating'] else 0 for trend in feedback_trends])
    
    # Ensure sentiment_summary has all required keys
    if not analytics.sentiment_summary:
        analytics.sentiment_summary = {'positive': 0, 'neutral': 0, 'negative': 0}
        analytics.save()
    
    # Ensure common_feedback_topics exists and is properly formatted
    if not analytics.common_feedback_topics:
        analytics.common_feedback_topics = {}
        analytics.save()
    
    # Convert common_feedback_topics to the format expected by d3.layout.cloud
    common_feedback_topics = json.dumps(analytics.common_feedback_topics)
    
    # Generate recommendations
    all_feedbacks = ServiceFeedback.objects.filter(
        service__vendor=vendor
    ).select_related(
        'service',
        'user',
        'sentiment'
    ).order_by(
        'service__name',
        '-created_at'
    )
    
    recommendations = generate_recommendations(all_feedbacks)
    
    context = {
        'analytics': analytics,
        'feedback_trends': feedback_trends,
        'vendor': vendor,
        'recent_feedbacks': recent_feedbacks,
        'negative_feedbacks': negative_feedbacks,
        'positive_feedbacks': positive_feedbacks,  
        'selected_days': days,
        'feedback_trends_dates': feedback_trends_dates,
        'feedback_trends_ratings': feedback_trends_ratings,
        'common_feedback_topics': common_feedback_topics,
        'recommendations': recommendations,
        'all_feedbacks': all_feedbacks
    }
    
    return render(request, 'feedback/analytics.html', context)

def generate_recommendations(feedbacks):
    # Initialize recommendation categories
    recommendations = {
        'critical': [],
        'important': [],
        'suggested': []
    }
    
    # Analyze feedback patterns
    feedback_patterns = {
        'service_quality': {'scores': [], 'comments': []},
        'communication': {'scores': [], 'comments': []},
        'value_for_money': {'scores': [], 'comments': []},
        'professionalism': {'scores': [], 'comments': []},
        'overall': {'scores': [], 'comments': []}
    }
    
    # Aggregate feedback by type
    for feedback in feedbacks:
        category = feedback.feedback_type
        if category in feedback_patterns:
            feedback_patterns[category]['scores'].append(feedback.rating)
            if hasattr(feedback, 'sentiment'):
                if feedback.sentiment.compound_score < -0.05:  # Negative sentiment
                    feedback_patterns[category]['comments'].append({
                        'text': feedback.text_feedback,
                        'sentiment': feedback.sentiment.compound_score,
                        'rating': feedback.rating
                    })
    
    # Generate recommendations based on patterns
    for category, data in feedback_patterns.items():
        if data['scores']:
            avg_score = sum(data['scores']) / len(data['scores'])
            negative_comments = [c for c in data['comments'] if c['sentiment'] < -0.05]
            
            # Critical issues (low scores and negative sentiment)
            if avg_score <= 3 and negative_comments:
                recommendations['critical'].append({
                    'category': category,
                    'score': avg_score,
                    'feedback': negative_comments[:3],  # Top 3 negative comments
                    'suggestion': get_improvement_suggestion(category, avg_score)
                })
            # Important improvements (moderate scores with negative feedback)
            elif avg_score <= 4 and negative_comments:
                recommendations['important'].append({
                    'category': category,
                    'score': avg_score,
                    'feedback': negative_comments[:2],  # Top 2 negative comments
                    'suggestion': get_improvement_suggestion(category, avg_score)
                })
            # Suggested enhancements (good scores but with some negative feedback)
            elif negative_comments:
                recommendations['suggested'].append({
                    'category': category,
                    'score': avg_score,
                    'feedback': negative_comments[:1],  # Top negative comment
                    'suggestion': get_improvement_suggestion(category, avg_score)
                })
    
    return recommendations

def get_improvement_suggestion(category, score):
    suggestions = {
        'service_quality': {
            'low': "Consider reviewing and standardizing service delivery processes. Focus on consistency and quality control.",
            'medium': "Look for opportunities to enhance service features and delivery methods.",
            'high': "Maintain high standards while exploring innovative service improvements."
        },
        'communication': {
            'low': "Implement a structured communication protocol. Consider response time improvements and clarity in messages.",
            'medium': "Enhance communication channels and frequency of updates to clients.",
            'high': "Fine-tune communication style and explore proactive update systems."
        },
        'value_for_money': {
            'low': "Review pricing strategy and service offerings. Consider package deals or added value services.",
            'medium': "Analyze cost-value relationship and identify areas for additional value.",
            'high': "Look for ways to add premium features while maintaining current pricing."
        },
        'professionalism': {
            'low': "Establish clear professional guidelines and conduct training sessions.",
            'medium': "Reinforce professional standards and customer service best practices.",
            'high': "Continue professional development and look for excellence opportunities."
        },
        'overall': {
            'low': "Conduct a comprehensive service audit and implement improvement action plan.",
            'medium': "Focus on specific areas of improvement while maintaining strengths.",
            'high': "Build on current success while exploring innovative enhancements."
        }
    }
    
    if score <= 3:
        return suggestions[category]['low']
    elif score <= 4:
        return suggestions[category]['medium']
    else:
        return suggestions[category]['high']

from django.shortcuts import render, redirect
import numpy as np
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from decimal import Decimal
from django.contrib import messages

def initialize_budget_model():
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(8,)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(8, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def optimize_budget(request):
    if not request.session.get('user_id'):
        return redirect('login')
    
    try:
        wedding_budget = WeddingBudget.objects.get(user_id=request.session['user_id'])
        allocations = BudgetAllocation.objects.filter(wedding_budget=wedding_budget)
        events = WeddingEvent.objects.filter(wedding_budget=wedding_budget)
        
        context = {
            'wedding_budget': wedding_budget,
            'allocations': allocations,
            'events': events,
            'total_spent': sum(a.actual_spent for a in allocations),
            'remaining_budget': wedding_budget.total_budget - sum(a.actual_spent for a in allocations)
        }
    except WeddingBudget.DoesNotExist:
        context = {}

    if request.method == 'POST':
        try:
            # Get form data
            total_budget = Decimal(request.POST.get('total_budget', '0').replace(',', ''))
            guest_count = int(request.POST.get('guest_count', '0'))
            wedding_type = request.POST.get('wedding_type', '')
            wedding_date = request.POST.get('wedding_date', '')
            location = request.POST.get('location', '')

            if not all([total_budget, guest_count, wedding_type, wedding_date, location]):
                raise ValueError("All fields are required")

            # Create or update wedding budget
            wedding_budget, created = WeddingBudget.objects.update_or_create(
                user_id=request.session['user_id'],
                defaults={
                    'total_budget': total_budget,
                    'guest_count': guest_count,
                    'wedding_type': wedding_type,
                    'wedding_date': wedding_date,
                    'location': location
                }
            )

            # Delete existing allocations and events if updating
            if not created:
                BudgetAllocation.objects.filter(wedding_budget=wedding_budget).delete()
                WeddingEvent.objects.filter(wedding_budget=wedding_budget).delete()

            # Create budget allocations
            allocation_percentages = {
                'Venue': Decimal('0.25'),
                'Catering': Decimal('0.30'),
                'Decoration': Decimal('0.15'),
                'Photography': Decimal('0.10'),
                'Attire': Decimal('0.08'),
                'Entertainment': Decimal('0.05'),
                'Mehendi': Decimal('0.04'),
                'Makeup': Decimal('0.03')
            }

            # Create allocations
            for category, percentage in allocation_percentages.items():
                amount = (total_budget * percentage).quantize(Decimal('0.01'))
                BudgetAllocation.objects.create(
                    wedding_budget=wedding_budget,
                    category=category,
                    allocated_amount=amount,
                    priority_level=1 if percentage >= Decimal('0.20') else (2 if percentage >= Decimal('0.10') else 3)
                )

            # Create wedding events
            default_events = [
                ('Engagement', Decimal('0.10')),
                ('Haldi', Decimal('0.05')),
                ('Mehendi', Decimal('0.15')),
                ('Sangeet', Decimal('0.20')),
                ('Wedding', Decimal('0.35')),
                ('Reception', Decimal('0.15'))
            ]

            # Convert wedding_date string to date object
            main_wedding_date = datetime.strptime(wedding_date, '%Y-%m-%d').date()

            # Create events with relative dates
            for event_name, budget_percentage in default_events:
                event_budget = (total_budget * budget_percentage).quantize(Decimal('0.01'))
                
                # Calculate event date based on wedding date
                if event_name == 'Wedding':
                    event_date = main_wedding_date
                elif event_name == 'Reception':
                    event_date = main_wedding_date + timedelta(days=1)
                elif event_name in ['Sangeet', 'Mehendi']:
                    event_date = main_wedding_date - timedelta(days=1)
                elif event_name == 'Haldi':
                    event_date = main_wedding_date - timedelta(days=2)
                else:  # Engagement
                    event_date = main_wedding_date - timedelta(days=30)

                # Create the event
                WeddingEvent.objects.create(
                    wedding_budget=wedding_budget,
                    event_name=event_name,
                    date=event_date,
                    budget=event_budget,
                    guest_count=guest_count if event_name in ['Wedding', 'Reception'] 
                              else int(guest_count * 0.7)
                )
                print(f"Created event: {event_name} on {event_date} with budget ₹{event_budget:,.2f}")

            messages.success(request, 'Budget and events created successfully!')
            
            # Update context with new data
            allocations = BudgetAllocation.objects.filter(wedding_budget=wedding_budget)
            events = WeddingEvent.objects.filter(wedding_budget=wedding_budget)
            context = {
                'wedding_budget': wedding_budget,
                'allocations': allocations,
                'events': events,
                'total_spent': sum(a.actual_spent for a in allocations),
                'remaining_budget': total_budget - sum(a.actual_spent for a in allocations)
            }

            return render(request, 'dreamknot1/optimize_budget.html', context)

        except ValueError as e:
            messages.error(request, f'Invalid input: {str(e)}')
        except Exception as e:
            print(f"Error creating budget: {str(e)}")
            messages.error(request, f'Error: {str(e)}')

    return render(request, 'dreamknot1/optimize_budget.html', context)
def view_budget(request):
    if not request.session.get('user_id'):
        return redirect('login')
    
    try:
        wedding_budget = WeddingBudget.objects.get(user_id=request.session['user_id'])
        allocations = BudgetAllocation.objects.filter(wedding_budget=wedding_budget)
        events = WeddingEvent.objects.filter(wedding_budget=wedding_budget)

        context = {
            'wedding_budget': wedding_budget,
            'allocations': allocations,
            'events': events,
            'total_spent': sum(a.actual_spent for a in allocations),
            'remaining_budget': wedding_budget.total_budget - sum(a.actual_spent for a in allocations)
        }
        return render(request, 'dreamknot1/view_budget.html', context)

    except WeddingBudget.DoesNotExist:
        messages.info(request, 'Please set up your wedding budget first.')
        return redirect('optimize_budget')

from .utils.budget_dataset import WeddingBudgetDataset

def train_budget_model():
    """Train the budget optimization model"""
    dataset = WeddingBudgetDataset()
    dataset.generate_synthetic_data()
    X_train, X_test, y_train, y_test, scaler = dataset.get_training_data()
    
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(6,)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(8, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='mse', metrics=['mae'])
    model.fit(X_train, y_train, epochs=50, batch_size=32, validation_split=0.2)
    
    return model, scaler


from django.db.models import Sum, Avg, Count
from django.db.models.functions import Coalesce

def budget_analytics(request):
    if not request.session.get('user_id'):
        return redirect('login')
    
    try:
        wedding_budget = WeddingBudget.objects.get(user_id=request.session['user_id'])
        allocations = BudgetAllocation.objects.filter(wedding_budget=wedding_budget)
        
        # Calculate overall budget metrics
        total_allocated = allocations.aggregate(Sum('allocated_amount'))['allocated_amount__sum'] or 0
        total_spent = allocations.aggregate(Sum('actual_spent'))['actual_spent__sum'] or 0
        
        try:
            total_savings = sum(alloc.calculate_savings() for alloc in allocations)
            percentage_spent = (total_spent / wedding_budget.total_budget * 100) if wedding_budget.total_budget else 0
            wedding_date = wedding_budget.wedding_date
            days_to_wedding = (wedding_date - datetime.now().date()).days if wedding_date else 0
        except (ZeroDivisionError, TypeError):
            total_savings = 0
            percentage_spent = 0
            days_to_wedding = 0
        
        # Get vendor recommendations
        recommendations = {}
        for alloc in allocations:
            if alloc.status in ['planning', 'in_progress']:
                recommended_vendors = alloc.get_recommended_vendors()[:3]
                if recommended_vendors:
                    recommendations[alloc.category] = recommended_vendors
        
        # Generate cost-saving tips
        tips = generate_cost_saving_tips(wedding_budget, allocations)
        
        context = {
            'wedding_budget': wedding_budget,
            'allocations': allocations,
            'total_allocated': total_allocated,
            'total_spent': total_spent,
            'total_savings': total_savings,
            'percentage_spent': percentage_spent,
            'days_to_wedding': days_to_wedding,
            'recommendations': recommendations,
            'tips': tips,
        }
        
        return render(request, 'dreamknot1/budget_analytics.html', context)
        
    except WeddingBudget.DoesNotExist:
        messages.info(request, 'Please set up your wedding budget first.')
        return redirect('optimize_budget')
    except Exception as e:
        messages.error(request, f'Error loading budget analytics: {str(e)}')
        return redirect('user_home')

def generate_cost_saving_tips(wedding_budget, allocations):
    """Generate personalized cost-saving tips based on budget analysis"""
    tips = []
    
    # Check if it's peak season
    wedding_month = wedding_budget.wedding_date.month
    if wedding_month in [11, 12, 1, 2]:
        tips.append({
            'category': 'Seasonal',
            'tip': 'Consider shifting your wedding date to off-peak season for better rates',
            'potential_savings': '15-20%'
        })
    
    # Check guest count optimization
    if wedding_budget.guest_count > 500:
        tips.append({
            'category': 'Guest List',
            'tip': 'Reducing guest count by 20% could significantly lower catering and venue costs',
            'potential_savings': '₹' + str(int(wedding_budget.total_budget * Decimal('0.15')))
        })
    
    # Venue optimization
    venue_alloc = allocations.filter(category='Venue').first()
    if venue_alloc and venue_alloc.status == 'planning':
        tips.append({
            'category': 'Venue',
            'tip': 'Consider booking morning slots or weekday venues for better rates',
            'potential_savings': '20-30%'
        })
    
    return tips
