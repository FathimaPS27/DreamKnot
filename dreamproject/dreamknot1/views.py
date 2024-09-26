from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.hashers import make_password, check_password
from .models import UserSignup, UserProfile, VendorProfile,WeddingTask,RSVPInvitation, VendorImage
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



def index(request):
    return render(request, 'dreamknot1/index.html')

@cache_control(no_cache=True, must_revalidate=True, no_store=True)

def user_home(request):
    user_name = request.session.get('user_name', 'user')  # Assuming you're storing the email in the session

    try:
        # Fetch the user instance using the session data
        user_instance = UserSignup.objects.get(name=user_name)  # Adjust if needed based on your session key
    except UserSignup.DoesNotExist:
        user_instance = None

    time_left = None
    wedding_date = None
    message = None

    # Check if the user instance exists and has a related UserProfile
    if user_instance:
        try:
            wedding_date = user_instance.userprofile.wedding_date
        except UserProfile.DoesNotExist:
            wedding_date = None

        # Calculate the time left if wedding_date is present
        if wedding_date:
            now = timezone.now()  # This is a timezone-aware datetime object
            
            # Convert wedding_date to a timezone-aware datetime
            wedding_datetime = timezone.make_aware(timezone.datetime.combine(wedding_date, timezone.datetime.min.time()))

            # Compare wedding_datetime and now
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

    return render(request, 'dreamknot1/user_home.html', {
        'name': user_name,
        'time_left': time_left,
        'wedding_date': wedding_date,
        'message': message
    })
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def vendor_home(request):
    user_name = request.session.get('user_name', 'vendor')
    return render(request, 'dreamknot1/vendor_home.html', {'name': user_name})


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

        # If there are errors, redirect back to the signup page with messages and the entered data
        if errors:
            return render(request, 'dreamknot1/signup.html', {
                'name': name,
                'email': email,
                'password': password,
                're_password': re_password,  # Re-populating re-entered password
                'country': country,
                'state': state,
                'place': place,
                'phone': phone,
                'role': role,
                'countries': countries,  # Assuming you have a list of countries
            })

        # Hash the password before saving
        hashed_password = make_password(password)

        # Save user if validation is passed
        user_signup = UserSignup(
            name=name,
            email=email,
            password=hashed_password,  # Save the hashed password
            country=country,
            state=state,
            place=place,
            phone=phone,
            role=role,
        )
        user_signup.save()
        messages.success(request, "Signup successful!")
        return redirect('login')

    # For GET requests, render the signup page
    context = {
        'countries': countries,  # Assuming you have a list of countries
    }
    return render(request, 'dreamknot1/signup.html', context)

# for login

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Find user by email
            user = UserSignup.objects.get(email=email)
            
            # Check if the password is correct
            if check_password(password, user.password):
                # Log the user in by setting session data
                request.session['user_id'] = user.id
                request.session['user_role'] = user.role
                request.session['user_name'] = user.name
                
                messages.success(request, "Login successful!")
                if user.role == 'admin':
                    return redirect('/admin')
                elif user.role == 'vendor':
                    return redirect('vendor_home')
                else:
                    return redirect('user_home')
            else:
                messages.error(request, "Invalid email or password.")
                return redirect('login')

        except UserSignup.DoesNotExist:
            messages.error(request, "Invalid email or password.")
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
                status=True  # You can set status based on your requirements
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

def todo_list(request):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')  # Redirect to login page if not logged in

    # Get the user instance
    user_instance = get_object_or_404(UserSignup, id=user_id)

    # Query the tasks associated with the current user
    user_tasks = WeddingTask.objects.filter(user=user_instance).order_by('-created_at')

    # Calculate completed and pending task counts
    completed_count = user_tasks.filter(is_completed=True).count()
    pending_count = user_tasks.filter(is_completed=False).count()

    # Render tasks with counts
    return render(request, 'dreamknot1/todo_list.html', {
        'tasks': user_tasks,
        'completed_count': completed_count,
        'pending_count': pending_count,
    })

def add_task(request):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to add a task.")
        return redirect('login')

    if request.method == 'POST':
        task_description = request.POST.get('task_description')
        task_month = request.POST.get('task_month')
        
        if task_description:  # Ensure the task description is not empty
            user_instance = get_object_or_404(UserSignup, id=user_id)
            WeddingTask.objects.create(user=user_instance, description=task_description, task_month=task_month)
            messages.success(request, "Task added successfully.")
            return redirect('todo_list')
        else:
            messages.error(request, "Task description cannot be empty.")

    return render(request, 'dreamknot1/add_task.html')

def update_task(request, task_id):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to update a task.")
        return redirect('login')

    # Get the task and ensure it belongs to the logged-in user
    task = get_object_or_404(WeddingTask, id=task_id, user__id=user_id)

    if request.method == 'POST':
        task.is_completed = not task.is_completed  # Toggle completion status
        task.save()
        messages.success(request, "Task updated successfully.")
        return redirect('todo_list')

    return render(request, 'dreamknot1/update_task.html', {'task': task})

def delete_task(request, task_id):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to delete a task.")
        return redirect('login')

    # Get the task and ensure it belongs to the logged-in user
    task = get_object_or_404(WeddingTask, id=task_id, user__id=user_id)
    
    task.delete()
    messages.success(request, "Task deleted successfully.")
    return redirect('todo_list')




def send_rsvp_invitation(request):
    couple_id = request.user.id  # Assuming the logged-in user is the couple

    if request.method == "POST":
        guest_name = request.POST.get("guest_name")
        guest_email = request.POST.get("guest_email")
        wedding_date = request.POST.get("wedding_date")  # You might get this from UserProfile
        venue = request.POST.get("venue")  # You might get this from UserProfile
        location = request.POST.get("location")  # You might get this from UserProfile
        time = request.POST.get("time")  # You might get this from UserProfile

        # Create the RSVP invitation entry
        invitation = RSVPInvitation.objects.create(
            couple=request.user,
            guest_name=guest_name,
            guest_email=guest_email,
            wedding_date=wedding_date,
            venue=venue,
            location=location,
            time=time
        )

        # Generate confirmation links
        accept_url = request.build_absolute_uri(reverse('rsvp_confirm', args=[invitation.id, 'yes']))
        decline_url = request.build_absolute_uri(reverse('rsvp_confirm', args=[invitation.id, 'no']))

        # Send email with the confirmation links
        send_mail(
            f"Wedding Invitation from {request.user.name}",
            f"You are invited to the wedding of {request.user.name} on {wedding_date} at {venue}, {location}. "
            f"The event will start at {time}.\n\n"
            f"Please confirm your attendance:\n"
            f"Accept: {accept_url}\n"
            f"Decline: {decline_url}\n",
            'noreply@dreamknot.com',  # Your configured email
            [guest_email],
            fail_silently=False,
        )

        return redirect('rsvp_success')

    return render(request, 'dreamknot1/send_rsvp_invitation.html')

def rsvp_confirm(request, invitation_id, response):
    invitation = get_object_or_404(RSVPInvitation, id=invitation_id)

    if response == 'yes':
        invitation.is_accepted = True
    elif response == 'no':
        invitation.is_accepted = False
    else:
        return HttpResponse("Invalid response")

    invitation.save()  # Save the guest's response to the database

    if invitation.is_accepted:
        message = f"Thank you for confirming! We look forward to seeing you at the wedding."
    else:
        message = f"We're sorry you won't be able to attend. Thank you for letting us know."

    return render(request, 'dreamknot1/rsvp_confirmation.html', {'message': message})


from django.shortcuts import render, redirect
from django.utils import timezone
from django.http import HttpResponse
from .models import VendorProfile, Service, ServiceImage, Booking, Rating, Favorite

# Vendor Dashboard - Add and Manage Services
def vendor_dashboard(request):
    vendor_name = request.session.get('user_name', 'vendor')

    try:
        vendor_instance = VendorProfile.objects.get(user__name=vendor_name)
        
        # Check if required profile details are missing
        if not vendor_instance.company_name or not vendor_instance.bio or not vendor_instance.business_category:
            # Add a flash message and redirect to the profile update page
            messages.warning(request, "Please complete your profile before accessing the dashboard.")
            return redirect('update_vendor_profile')  # Redirect to the profile update page

    except VendorProfile.DoesNotExist:
        # Add a flash message and redirect to the profile update page if profile does not exist
        messages.warning(request, "Vendor not found. Please add your details in the profile first.")
        return redirect('update_vendor_profile')

    # Fetch services related to the vendor
    services = Service.objects.filter(vendor=vendor_instance)

    # Initialize empty error dictionary and variables to retain form data
    errors = {}
    service_name = ""
    description = ""
    price = ""
    category = ""
    availability = False

    if request.method == "POST":
        service_name = request.POST.get('name', '')
        description = request.POST.get('description', '')
        price = request.POST.get('price', '')
        category = request.POST.get('category', '')
        availability = 'availability' in request.POST  # Checkbox handling

        # Validate inputs
        if not re.match(r'^[A-Za-z\s]+$', service_name):
            errors['name'] = "Service name can only contain alphabets and spaces."
        if not price:
            errors['price'] = "Price is required."
        else:
            try:
                price_value = float(price)
                if price_value <= 0:
                    errors['price'] = "Price must be a positive number."
            except ValueError:
                errors['price'] = "Invalid price format."

        # If there are no errors, save the service
        if not errors:
            service = Service(
                vendor=vendor_instance,
                name=service_name,
                description=description,
                price=price_value,
                category=category,
                availability=availability,
                created_at=timezone.now(),
            )
            service.save()

            if 'image' in request.FILES:
                image = request.FILES['image']
                service_image = ServiceImage(service=service, image=image)
                service_image.save()

            return redirect('vendor_dashboard')

    return render(request, 'dreamknot1/vendor_dashboard.html', {
        'services': services,
        'vendor_name': vendor_name,
        'errors': errors,
        'form_data': {
            'name': service_name,
            'description': description,
            'price': price,
            'category': category,
            'availability': availability,
        },
    })
def edit_service(request, service_id):
    # Fetch the service instance
    service = get_object_or_404(Service, id=service_id)
    vendor_name = request.session.get('user_name', 'vendor')
    
    # Ensure the user is the owner of the service
    if service.vendor.user.name != vendor_name:
        return HttpResponse("You do not have permission to edit this service.")

    if request.method == "POST":
        # Validate and update service fields
        service.name = request.POST['name']
        service.description = request.POST['description']
        service.price = request.POST['price']
        service.category = request.POST['category']
        
        # Check availability based on the presence of the checkbox
        service.availability = 'availability' in request.POST

        # Validate fields
        if not service.name or not service.description or not service.price or not service.category:
            return render(request, 'dreamknot1/edit_service.html', {
                'service': service,
                'error_message': "All fields are required."
            })
        
        # Save the updated service
        service.updated_at = timezone.now()
        service.save()

        # Handle image upload (if a new image is uploaded)
        if 'image' in request.FILES:
            # Delete existing image if necessary
            ServiceImage.objects.filter(service=service).delete()  # You can choose to keep this or just overwrite
            image = request.FILES['image']
            service_image = ServiceImage(service=service, image=image)
            service_image.save()

        return redirect('vendor_dashboard')

    return render(request, 'dreamknot1/edit_service.html', {'service': service})
# Delete Service
def delete_service(request, service_id):
    try:
        service = Service.objects.get(id=service_id)
        service.delete()
        return redirect('vendor_dashboard')
    except Service.DoesNotExist:
        return HttpResponse("Service not found.")
    

    # User Dashboard - View Vendor Services, Book, Rate, Favorite
def user_dashboard(request):
    user_name = request.session.get('user_name', 'user')
    services = Service.objects.filter(status=1, availability=True)  # Only active services

    # Filter services by category
    if 'category' in request.GET:
        category = request.GET['category']
        services = services.filter(category=category)

    # Search services
    if 'search' in request.GET:
        search_query = request.GET['search']
        services = services.filter(name__icontains=search_query)

    # Get vendors and related services
    vendor_services = {}
    for service in services:
        vendor = service.vendor
        vendor_services.setdefault(vendor, []).append(service)

    return render(request, 'dreamknot1/user_dashboard.html', {
        'vendor_services': vendor_services,
        'user_name': user_name,
    })
def vendor_services(request, vendor_id):
    vendor = get_object_or_404(VendorProfile, id=vendor_id)
    services = Service.objects.filter(vendor=vendor, status=1, availability=True)
    return render(request, 'dreamknot1/vendor_services.html', {'vendor': vendor, 'services': services})

def service_detail(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    return render(request, 'dreamknot1/service_detail.html', {'service': service})
# Book a Service
def book_service(request, service_id):
    user_name = request.session.get('user_name', 'user')
    
    try:
        service = Service.objects.get(id=service_id)
        user = UserSignup.objects.get(name=user_name)
        user_profile = UserProfile.objects.get(user=user)
    except Service.DoesNotExist:
        return HttpResponse("Service not found.")
    except UserSignup.DoesNotExist:
        return HttpResponse("User not found.")
    except UserProfile.DoesNotExist:
        user_profile = None  # In case the user profile is not yet created

    if request.method == "POST":
        event_date = request.POST.get('event_date')
        address = request.POST.get('address', user.place)  # Use the user's existing address as default
        phone_number = request.POST.get('phone', user.phone)
        email = request.POST.get('email', user.email)

        # Update the wedding date if provided by the user
        wedding_date = request.POST.get('wedding_date')
        if wedding_date and user_profile:
            user_profile.wedding_date = wedding_date
            user_profile.save()

        # Book the service
        booking = Booking(user=user, service=service, event_date=event_date)
        booking.save()

        return redirect('user_dashboard')

    return render(request, 'dreamknot1/book_service.html', {
        'service': service,
        'user': user,
        'user_profile': user_profile
    })

# Add to Favorite
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

# Rate a Service
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

