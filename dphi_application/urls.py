from . import views
from django.urls import path

urlpatterns = [
    path('check/', views.index, name="index"),
    path('user/signup', views.user_signup, name="user_signup"),
]