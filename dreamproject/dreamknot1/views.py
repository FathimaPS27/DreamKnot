from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.hashers import make_password, check_password
from .models import UserSignup, UserProfile, VendorProfile,WeddingTask,RSVPInvitation, VendorImage,Favorite, Booking
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
        verification_code = str(uuid.uuid4())

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
        verification_link = request.build_absolute_uri(f"/verify-email/{verification_code}/")
        send_mail(
            'Email Verification - Dream Knot',
            f'Please verify your email by clicking on this link: {verification_link}',
            settings.EMAIL_HOST_USER,
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


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import WeddingTask, UserSignup, UserProfile
from django.db.models import Q
from datetime import timedelta, date


def current_month_todolist(request):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')

    # Get the user instance
    user_instance = get_object_or_404(UserSignup, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user_instance)

    # Check if the wedding date is set
    if not user_profile.wedding_date:
        messages.warning(request, "Please set your wedding date to view tasks.")
        return redirect('profile_update')

    # Get the current date and wedding date
    today = timezone.now().date()
    wedding_date = user_profile.wedding_date

    # Calculate remaining days until the wedding
    remaining_days = (wedding_date - today).days

    # Determine which task range to filter based on remaining days
    if remaining_days > 180:  # More than 6 months left
        current_month = '6-12'
    elif 120 < remaining_days <= 180:  # 4-6 months left
        current_month = '4-6'
    elif 60 < remaining_days <= 120:  # 2-4 months left
        current_month = '2-4'
    elif 30 < remaining_days <= 60:  # 1-2 months left
        current_month = '1-2'
    elif 14 < remaining_days <= 30:  # 1-2 weeks left
        current_month = '1-2 Weeks'
    else:  # Final days
        current_month = 'Final Days'

    # Fetch user-specific tasks
    user_tasks = WeddingTask.objects.filter(user=user_instance, task_month=current_month)

    # Fetch predefined tasks (tasks that are not tied to a specific user)
    predefined_tasks = WeddingTask.objects.filter(user=None, task_month=current_month)

    # Combine both user-specific and predefined tasks
    all_tasks = user_tasks | predefined_tasks

    # Separate pending and completed tasks
    pending_tasks = all_tasks.filter(is_completed=False)
    completed_tasks = all_tasks.filter(is_completed=True)

    # Calculate completed and pending task counts for display
    completed_count = completed_tasks.count()
    pending_count = pending_tasks.count()

    # Overall counts for all tasks (not just the current month)
    overall_completed_count = WeddingTask.objects.filter(user=user_instance, is_completed=True).count() + WeddingTask.objects.filter(user=None, is_completed=True).count()
    overall_pending_count = WeddingTask.objects.filter(user=user_instance, is_completed=False).count() + WeddingTask.objects.filter(user=None, is_completed=False).count()

    # Rendering the template with the current month's tasks
    return render(request, 'dreamknot1/current_month_todolist.html', {
        'pending_tasks': pending_tasks,  # Tasks that are still pending
        'completed_tasks': completed_tasks,  # Tasks that are completed
        'wedding_month': current_month,  # The current task month
        'today': today,  # Today's date
        'completed_count': completed_count,  # Count of completed tasks for the month
        'pending_count': pending_count,  # Count of pending tasks for the month
        'overall_completed_count': overall_completed_count,  # Total completed tasks overall
        'overall_pending_count': overall_pending_count,  # Total pending tasks overall
    })



def todo_list(request):
    # Check if the user is logged in
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to view your tasks.")
        return redirect('login')

    # Get the user instance
    user_instance = get_object_or_404(UserSignup, id=user_id)

    # Get the user profile instance
    user_profile = get_object_or_404(UserProfile, user=user_instance)

    # Check if the wedding date is set
    if not user_profile.wedding_date:
        messages.warning(request, "Please set your wedding date to view tasks.")
        return redirect('profile_update')

    # Calculate the number of days until the wedding date
    remaining_days = (user_profile.wedding_date - timezone.now().date()).days

    # Fetch all tasks for the user and predefined tasks
    user_tasks = WeddingTask.objects.filter(user=user_instance)
    predefined_tasks = WeddingTask.objects.filter(user=None)

    # Combine user tasks and predefined tasks
    tasks = user_tasks | predefined_tasks

    # Filter tasks based on months left (but still show past tasks)
    current_tasks = tasks.filter(
        Q(task_month='6-12', is_completed=False) & Q(user=user_instance) if remaining_days > 180 else
        Q(task_month='4-6', is_completed=False) & Q(user=user_instance) if 120 < remaining_days <= 180 else
        Q(task_month='2-4', is_completed=False) & Q(user=user_instance) if 60 < remaining_days <= 120 else
        Q(task_month='1-2', is_completed=False) & Q(user=user_instance) if 30 < remaining_days <= 60 else
        Q(task_month='1-2 Weeks', is_completed=False) & Q(user=user_instance) if 14 < remaining_days <= 30 else
        Q(task_month='Final Days', is_completed=False) & Q(user=user_instance)
    )
 
    # Allow access to past tasks
    past_tasks = tasks.filter(is_completed=True)

    # Calculate completed and pending task counts (for user-specific tasks only)
    completed_count = tasks.filter(is_completed=True).count()
    pending_count = tasks.filter(is_completed=False).count()

    return render(request, 'dreamknot1/todo_list.html', {
        'tasks': tasks,  # All tasks (including past)
        'current_tasks': current_tasks,  # Current tasks based on months left
        'past_tasks': past_tasks,  # Past tasks that were completed
        'completed_count': completed_count,
        'pending_count': pending_count,
    })
def add_task(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to add a task.")
        return redirect('login')

    user_instance = get_object_or_404(UserSignup, id=user_id)

    # Get the user profile instance
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

def update_task(request, task_id):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to update a task.")
        return redirect('login')

    task = get_object_or_404(WeddingTask, id=task_id, user__id=user_id)

    if request.method == 'POST':
        task.is_completed = not task.is_completed  # Toggle completion status
        task.save()
        messages.success(request, "Task updated successfully.")
        return redirect('todo_list')

    return render(request, 'dreamknot1/update_task.html', {'task': task})


def delete_task(request, task_id):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must be logged in to delete a task.")
        return redirect('login')

    task = get_object_or_404(WeddingTask, id=task_id)

    # Prevent deletion of predefined tasks
    if task.user is None:  # Predefined tasks have user=None
        messages.error(request, "Predefined tasks cannot be deleted.")
        return redirect('todo_list')

    # Only allow deletion of user-added tasks
    if task.user_id != user_id:
        messages.error(request, "You can only delete your own tasks.")
        return redirect('todo_list')

    task.delete()
    messages.success(request, "Task deleted successfully.")
    return redirect('todo_list')


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

def send_rsvp_invitation(request):
    if not request.session.get('user_id'):
        return redirect('login')

    couple = UserSignup.objects.get(id=request.session['user_id'])

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

        messages.success(request, 'Invitations sent successfully to all guests!')
        return redirect('rsvp_success')

    return render(request, 'dreamknot1/send_rsvp_invitation.html')


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


def invitation_list(request):
    if not request.session.get('user_id'):
        return redirect('login')

    couple = UserSignup.objects.get(id=request.session['user_id'])
    invitations = RSVPInvitation.objects.filter(couple=couple)

    return render(request, 'dreamknot1/invitation_list.html', {'invitations': invitations})


def rsvp_success(request):
    return render(request, 'dreamknot1/rsvp_success.html')

from django.shortcuts import render, redirect
from django.utils import timezone
from django.http import HttpResponse
from .models import VendorProfile, Service, ServiceImage, Booking, Rating, Favorite



# Vendor Dashboard - Add and Manage Services
# Vendor Dashboard - Add and Manage Services
def vendor_dashboard(request):
    vendor_name = request.session.get('user_name', 'vendor')

    try:
        vendor_instance = VendorProfile.objects.get(user__name=vendor_name)
        
        # Check if required profile details are missing
        if not vendor_instance.company_name or not vendor_instance.bio or not vendor_instance.business_category:
            messages.warning(request, "Please complete your profile before accessing the dashboard.")
            return redirect('update_vendor_profile')

    except VendorProfile.DoesNotExist:
        messages.warning(request, "Vendor not found. Please add your details in the profile first.")
        return redirect('update_vendor_profile')

    # Fetch services and related bookings
    services = Service.objects.filter(vendor=vendor_instance)
    bookings = Booking.objects.filter(service__in=services)

    # Initialize empty error dictionary and variables to retain form data
    errors = {}
    service_name = description = price = category = ""
    availability = False

    if request.method == "POST":
        service_name = request.POST.get('name', '')
        description = request.POST.get('description', '')
        price = request.POST.get('price', '')
        category = request.POST.get('category', '')
        availability = 'availability' in request.POST

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

        # Save the service if no errors
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
        'bookings': bookings,
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

    # Get vendors and related services
    vendor_services = {}
    for service in services:
        vendor = service.vendor
        vendor_services.setdefault(vendor, []).append(service)

    # Fetch favorite services for the logged-in user
    favorites = Favorite.objects.filter(user=user).select_related('service')
    
    # Fetch bookings for the logged-in user
    bookings = Booking.objects.filter(user=user).select_related('service')

    return render(request, 'dreamknot1/user_dashboard.html', {
        'vendor_services': vendor_services,
        'user_name': user_name,
        'favorites': favorites,
        'bookings': bookings,
    })

def vendor_services(request, vendor_id):
    vendor = get_object_or_404(VendorProfile, id=vendor_id)
    services = Service.objects.filter(vendor=vendor, status=1, availability=True)
    return render(request, 'dreamknot1/vendor_services.html', {'vendor': vendor, 'services': services})

def service_detail(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    vendor_phone = service.vendor.user.phone  # Adjust if necessary

    return render(request, 'dreamknot1/service_detail.html', {
        'service': service,
        'vendor_phone': vendor_phone,  # Pass the vendor phone number to the template
    })

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Booking

from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.utils import timezone
from .models import Booking  # Assuming Booking model is in the same app

def vendor_approve_booking(request):
    # Check if user_id exists in session
    user_id = request.session.get('user_id')
    
    if user_id:
        try:
            vendor_instance = VendorProfile.objects.get(user__id=user_id)
            
            # Fetch bookings related to this vendor's services
            bookings = Booking.objects.filter(service__vendor=vendor_instance)
            
            return render(request, 'dreamknot1/vendor_approve_booking.html', {'bookings': bookings})

        except VendorProfile.DoesNotExist:
            messages.warning(request, "Vendor profile not found. Please complete your profile.")
            return redirect('update_vendor_profile')

    else:
        messages.warning(request, "You need to log in to access this page.")
        return redirect('login')  # Redirect to the login page


from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta

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

    # Logic for available slots (e.g., next 30 days)
    today = timezone.now().date()
    future_dates = [today + timedelta(days=i) for i in range(30)]  # Next 30 days
    booked_dates = bookings.values_list('event_date', flat=True)  # Already booked dates

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

# View to render the calendar and form page
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
    future_dates = [today + timedelta(days=i) for i in range(30)]  # Next 30 days
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
from .models import Booking
from django.utils import timezone

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Booking, UserSignup
from django.utils import timezone

def user_booking_details(request):
    # Get the current logged-in user based on 'user_name' from session
    user_name = request.session.get('user_name')
    
    # If no user is found in session, redirect to login
    if not user_name:
        return redirect('login')  # Redirect to login if the user is not authenticated
    
    # Get the logged-in user object
    user_signup = get_object_or_404(UserSignup, name=user_name)
    
    # Fetch all bookings for the logged-in user
    bookings = Booking.objects.filter(user=user_signup)
    
    # If the request is POST, handle booking cancellation
    if request.method == 'POST':
        booking_id = request.POST.get('booking_id')
        cancellation_reason = request.POST.get('cancellation_reason')
        
        # Get the booking object for the current user
        booking = get_object_or_404(Booking, id=booking_id, user=user_signup)
        
        # Update booking status and save the cancellation details
        booking.book_status = 3
        booking.canceled_by_user = True
        booking.cancellation_reason = cancellation_reason
        booking.vendor_confirmed_at = None  # Reset vendor confirmation if needed
        booking.save()

        # Display success message after cancellation
        messages.success(request, "Your booking has been canceled successfully.")
        return redirect('user_booking_details')

    # Render the booking details page
    return render(request, 'dreamknot1/user_booking_details.html', {
        'bookings': bookings,
    })























from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Service, UserSignup, UserProfile, Booking
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import Service, UserSignup, UserProfile, Booking
from django.utils import timezone

def book_service(request, service_id):
    # Get the user's name from the session
    user_name = request.session.get('user_name', 'user')

    try:
        # Fetch the service being booked
        service = Service.objects.get(id=service_id)
        
        # Fetch the user making the booking
        user = UserSignup.objects.get(name=user_name)
        
        # Fetch the user's profile, if it exists
        user_profile = UserProfile.objects.get(user=user)

    # Handle cases where the service or user is not found
    except Service.DoesNotExist:
        return HttpResponse("Service not found.")
    except UserSignup.DoesNotExist:
        return HttpResponse("User not found.")
    except UserProfile.DoesNotExist:
        user_profile = None  # If no user profile, leave it as None

    # If the request is a POST request, process the form data
    if request.method == "POST":
        # Get event details from the form
        event_date = request.POST.get('event_date')
        event_address = request.POST.get('event_address')  # Retrieve event address from form
        phone_number = request.POST.get('phone', user.phone)  # Default to user's saved phone
        email = request.POST.get('email', user.email)  # Default to user's saved email

        # If the user provides a wedding date and they have a profile, update it
        wedding_date = request.POST.get('wedding_date')
        if wedding_date and user_profile:
            user_profile.wedding_date = wedding_date
            user_profile.save()

        # Create a new booking entry (status defaults to 'Pending')
        booking = Booking(
            user=user,
            service=service,
            event_date=event_date,
            event_address=event_address,  # Use the event address from the form
            book_status=0  # Pending status
        )
        booking.save()

        # Redirect to the user's dashboard after booking
        return redirect('user_dashboard')

    # Render the booking form, pre-filling user and service details
    return render(request, 'dreamknot1/book_service.html', {
        'service': service,
        'user': user,
        'user_profile': user_profile,  # Could be None if the profile doesn't exist
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
    return render(request, 'dreamknot1/favorite_list.html', {'favorites': favorites})

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






from django.shortcuts import render, redirect
from django.shortcuts import render, get_object_or_404, redirect
from django.core.paginator import Paginator
# from django.contrib.auth.decorators import login_required
from .models import Service, UserSignup

# Admin Dashboard View (restricted to superusers)
def admin_dashboard(request):
        return render(request, 'dreamknot1/admin_dashboard.html')


from django.shortcuts import render
from .models import UserSignup

def view_users(request):
    role_filter = request.GET.get('role', 'user')  # Default to 'user' if no filter is applied

    if role_filter == 'vendor':
        users = UserSignup.objects.filter(role='vendor')
    else:
        users = UserSignup.objects.filter(role='user')

    context = {
        'users': users,
        'role_filter': role_filter,
    }
    return render(request, 'dreamknot1/view_users.html', context)


from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from .models import UserSignup

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

