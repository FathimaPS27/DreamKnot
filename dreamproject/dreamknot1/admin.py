from django.contrib import admin
from unfold.admin import ModelAdmin  # Ensure this is imported correctly
from django.contrib.auth.hashers import make_password
from .models import UserSignup  # Ensure the correct model name is being used

@admin.register(UserSignup)
class UserSignupAdmin(ModelAdmin):
    # Display relevant fields for the UserSignup model
    list_display = (
        'name', 
        'email', 
        'country',  
        'state',    
        'place',    
        'phone', 
        'role',     
        'status', 
        'created_at', 
        'updated_at'
    )
    
    # Add filters for efficient management
    list_filter = ('country', 'status', 'created_at', 'updated_at', 'role')  # Added 'role' to filter by roles (e.g. vendor, user)

    # Enable searching by name, email, place, and phone
    search_fields = ('name', 'email', 'place', 'phone')
    
    # Organize fields into sections for a better admin panel interface
    fieldsets = (
        (None, {
            'fields': ('name', 'email', 'password', 'country', 'state', 'place', 'phone', 'role', 'status')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),  # Make this section collapsible for cleaner UI
        }),
    )
    
    # Make certain fields read-only
    readonly_fields = ('created_at', 'updated_at')

    # Overriding save_model to hash the password if the user is being created
    def save_model(self, request, obj, form, change):
        if not change:  # Only hash password when creating a new user
            obj.password = make_password(obj.password)
        super().save_model(request, obj, form, change)

    # Restricting edit permissions (non-superuser cannot edit a user)
    def has_change_permission(self, request, obj=None):
        if obj and obj.pk:  # Check if the object exists
            if request.user.is_superuser:
                return True  # Superusers have full permissions
            return False  # Non-superusers can't edit
        return super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser