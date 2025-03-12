from django.urls import path, include
from . import views
from .views import login_view, signup,verify_email,book_service
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),# Add this for allauth
    path('login/', login_view, name='login'),
    path('signup/', signup, name='signup'),
    path('verify-email/<str:verification_code>/', verify_email, name='verify_email'),
    path('logout/', views.logout_view, name='logout'),
    path('user_home/', views.user_home, name='user_home'),
    path('vendor_home/', views.vendor_home, name='vendor_home'),
    path('user/profile/', views.update_user_profile, name='update_user_profile'),
    path('vendor/profile/', views.update_vendor_profile, name='update_vendor_profile'),
    path('vendor/image/delete/<int:image_id>/',views.delete_vendor_image, name='delete_vendor_image'),
    path('get-vendor-bookings/', views.get_vendor_bookings, name='get_vendor_bookings'),
    path('readmore/', views.readmore, name='readmore'),  # Service details page
    path('social-auth/', include('social_django.urls', namespace='social')),
    path('wedding-blogs/', views.wedding_blogs_view, name='wedding_blogs'),


    path('chatbot/', views.chatbot_response, name='chatbot_response'),
    path('generate-image/', views.generate_image, name='generate_image'),
    path('search-by-image/', views.search_by_image, name='search_by_image'),
    path('download-invoice/<int:booking_id>/', views.download_invoice, name='download_invoice'),

    path('user/rate/<int:service_id>/', views.rate_service, name='rate_service'),

    path('feedback/<int:booking_id>/', views.submit_service_feedback, name='submit_service_feedback'),
    path('vendor/analytics/<int:vendor_id>/', views.view_vendor_analytics, name='vendor_analytics'),


    #admin
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('view-users/', views.view_users, name='view_users'),
    path('toggle_status/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('manage_predefined_tasks/', views.manage_predefined_tasks, name='manage_predefined_tasks'),
    path('service/<int:service_id>/', views.admin_service_details, name='admin_service_details'),
    path('analytics/', views.admin_analytics, name='admin_analytics'),


    # path('view_venues/', views.view_venues, name='view_venues'),
    # path('edit_venue/<int:id>/', views.edit_venue, name='edit_venue'),
    # path('delete_venue/<int:id>/', views.delete_venue, name='delete_venue'),
    # path('view_bookings/', views.view_bookings, name='view_bookings'),
    # path('view_vendors/', views.view_vendors, name='view_vendors'),   
    # path('admin_logout/', views.admin_logout, name='admin_logout'),

    path('forgotpass/', views.forgotpass, name='forgotpass'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('todo/current/', views.current_month_todolist, name='current_month_todolist'),  # Current month tasks page
    path('todo/', views.todo_list, name='todo_list'),  # Full to-do list page
    path('todo/add/', views.add_task, name='add_task'),
    path('todo/update/<int:task_id>/', views.update_task, name='update_task'),
    path('todo/delete/<int:task_id>/', views.delete_task, name='delete_task'),
    
    path('send-invitation/', views.send_rsvp_invitation, name='send_rsvp_invitation'),
    path('invitations/', views.invitation_list, name='invitation_list'),
    path('rsvp-success/', views.rsvp_success, name='rsvp_success'),

    path('vendor/', views.vendor_dashboard, name='vendor_dashboard'),
    path('vendor/delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
    path('vendor/edit_service/<int:service_id>/', views.edit_service, name='edit_service'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('vendor_services/<int:vendor_id>/', views.vendor_services, name='vendor_services'),
    path('service_detail/<int:service_id>/', views.service_detail, name='service_detail'), 
    path('vendor/approve-booking/', views.vendor_approve_booking, name='vendor_approve_booking'),
    path('vendor/process-booking/', views.process_booking, name='process_booking'),
    path('get-booking-details/<int:booking_id>/', views.get_booking_details, name='get_booking_details'),
    path('vendor/calendar/<int:service_id>/', views.booking_calendar_view, name='booking_calendar'),
    path('delete-service-image/<int:image_id>/', views.delete_service_image, name='delete_service_image'),
    


    path('service/<int:service_id>/calendar/', views.booking_calendar_view, name='booking_calendar'),
    path('get-booking-slots/<int:service_id>/', views.get_booking_slots, name='get_booking_slots'),
    path('submit-booking/<int:service_id>/', views.submit_booking, name='submit_booking'),
    path('check_date_availability/<int:service_id>/', views.check_date_availability, name='check_date_availability'),

   
    path('user/book/<int:service_id>/', views.book_service, name='book_service'),
    path('user/favorite/<int:service_id>/', views.add_to_favorite, name='add_to_favorite'),
    path('user/rate/<int:service_id>/', views.rate_service, name='rate_service'),
    path('user/favorites/', views.favorite_list, name='favorite_list'),
    path('user/bookings/', views.user_booking_details, name='user_booking_details'),
    path('remove-from-favorite/<int:service_id>/', views.remove_from_favorite, name='remove_from_favorite'),

    path('payment_success/', views.payment_success, name='payment_success'),
    path('cancel_booking/<int:booking_id>/', views.cancel_booking, name='cancel_booking'),

    path('budget/optimize/', views.optimize_budget, name='optimize_budget'),
    path('budget/view/', views.view_budget, name='view_budget'),
    path('budget/analytics/', views.budget_analytics, name='budget_analytics'),
    path('update-priority/', views.update_priority, name='update_priority'),
    path('budget/export-report/', views.export_budget_report, name='export_budget_report'),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

