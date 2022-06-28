from . import views
from django.urls import path

urlpatterns = [
    path('check/', views.index, name="index"),
    path('user/signup', views.user_signup, name="user_signup"),
    path('user/login', views.user_login, name="user_login"),
    path('educator/signup', views.educator_signup, name="educator_signup"),
    path('educator/login', views.educator_login, name="educator_login"),

]
