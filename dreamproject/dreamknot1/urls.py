from django.urls import path
from . import views
from .views import login_view, signup,logout_view
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', login_view, name='login'),
    path('signup/', signup, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('user_home/', views.user_home, name='user_home'),
    path('vendor_home/', views.vendor_home, name='vendor_home'),
    path('user/profile/', views.update_user_profile, name='update_user_profile'),
    path('vendor/profile/', views.update_vendor_profile, name='update_vendor_profile'),
    path('vendor/image/delete/<int:image_id>/',views.delete_vendor_image, name='delete_vendor_image'),

    #admin
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('view-users/', views.view_users, name='view_users'),
    path('toggle_status/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),

    

    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),



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
    path('user/book/<int:service_id>/', views.book_service, name='book_service'),
    path('user/favorite/<int:service_id>/', views.add_to_favorite, name='add_to_favorite'),
    path('user/rate/<int:service_id>/', views.rate_service, name='rate_service'),
    path('user/favorites/', views.favorite_list, name='favorite_list')

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

