from social_core.exceptions import AuthAlreadyAssociated
from .models import UserSignup
from django.contrib.auth.hashers import make_password
import uuid
from django.shortcuts import redirect
from django.contrib import messages
from social_core.pipeline.partial import partial
from social_django.models import UserSocialAuth

def get_username(strategy, details, backend, user=None, *args, **kwargs):
    return {'username': details.get('email')}

@partial
def create_user(strategy, details, backend, user=None, *args, **kwargs):
    email = details.get('email')
    if not email:
        strategy.session_set('error_message', 'Email is required')
        return redirect('login')

    # Check if social auth already exists
    social = UserSocialAuth.objects.filter(
        provider='google-oauth2',
        uid=details.get('sub')
    ).first()

    if social:
        # Social auth exists, set session and return user
        user = social.user
        if isinstance(user, UserSignup):
            strategy.session_set('user_id', user.id)
            strategy.session_set('user_name', user.name)
            strategy.session_set('user_role', user.role)
            strategy.session_set('is_social', True)
            return {
                'is_new': False,
                'user': user,
                'social': social
            }

    try:
        # Check if user exists by email
        existing_user = UserSignup.objects.get(email=email)
        
        # Update existing user's social info
        existing_user.is_social_user = True
        existing_user.is_verified = True
        existing_user.google_id = details.get('sub')
        existing_user.save()

        # Set session variables
        strategy.session_set('user_id', existing_user.id)
        strategy.session_set('user_name', existing_user.name)
        strategy.session_set('user_role', existing_user.role)
        strategy.session_set('is_social', True)

        return {
            'is_new': False,
            'user': existing_user
        }

    except UserSignup.DoesNotExist:
        try:
            # Create new user
            new_user = UserSignup(
                email=email,
                name=details.get('fullname', '') or details.get('email').split('@')[0],
                password=make_password(uuid.uuid4().hex),
                country='IN',
                state='',
                place='',
                phone='',
                role='user',
                is_verified=True,
                status=True,
                is_social_user=True,
                google_id=details.get('sub')
            )
            new_user.save()

            # Set session variables
            strategy.session_set('user_id', new_user.id)
            strategy.session_set('user_name', new_user.name)
            strategy.session_set('user_role', new_user.role)
            strategy.session_set('is_social', True)

            return {
                'is_new': True,
                'user': new_user
            }
        except Exception as e:
            strategy.session_set('error_message', str(e))
            return redirect('login')

def update_user_details(strategy, details, backend, user=None, *args, **kwargs):
    if not user:
        return

    try:
        # Update session
        strategy.session_set('user_id', user.id)
        strategy.session_set('user_name', user.name)
        strategy.session_set('user_role', user.role)
        strategy.session_set('is_social', True)
        
        return {
            'user': user,
            'next': '/user_home/'
        }
    except Exception as e:
        strategy.session_set('error_message', str(e))
        return redirect('login')