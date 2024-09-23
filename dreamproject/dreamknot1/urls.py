from django.urls import path
from . import views
from .views import login_view, signup,logout_view, todo_list, add_task, update_task, delete_task

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', login_view, name='login'),
    path('signup/', signup, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('user_home/', views.user_home, name='user_home'),
    path('vendor_home/', views.vendor_home, name='vendor_home'),
    path('user/profile/', views.update_user_profile, name='update_user_profile'),
    path('vendor/profile/', views.update_vendor_profile, name='update_vendor_profile'),
    path('forgotpass/', views.forgotpass, name='forgotpass'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('todo/', todo_list, name='todo_list'),
    path('todo/add/', add_task, name='add_task'),
    path('todo/update/<int:task_id>/', update_task, name='update_task'),
    path('todo/delete/<int:task_id>/', delete_task, name='delete_task'),
]

