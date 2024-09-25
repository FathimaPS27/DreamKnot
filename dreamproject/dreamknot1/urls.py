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

    path('forgotpass/', views.forgotpass, name='forgotpass'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('todo/', views.todo_list, name='todo_list'),
    path('add_task/', views.add_task, name='add_task'),
    path('update_task/<int:task_id>/', views.update_task, name='update_task'),
    path('delete_task/<int:task_id>/', views.delete_task, name='delete_task'),
    path('send-invitation/', views.send_rsvp_invitation, name='send_rsvp_invitation'),
    path('rsvp/<int:invitation_id>/<str:response>/', views.rsvp_confirm, name='rsvp_confirm'),

    path('vendor/', views.vendor_dashboard, name='vendor_dashboard'),
    path('vendor/delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
    path('vendor/edit_service/<int:service_id>/', views.edit_service, name='edit_service'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('vendor_services/<int:vendor_id>/', views.vendor_services, name='vendor_services'),
    path('service_detail/<int:service_id>/', views.service_detail, name='service_detail'), 
    path('user/book/<int:service_id>/', views.book_service, name='book_service'),
    path('user/favorite/<int:service_id>/', views.add_to_favorite, name='add_to_favorite'),
    path('user/rate/<int:service_id>/', views.rate_service, name='rate_service'),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

