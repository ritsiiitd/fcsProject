from django.contrib import admin
from django.urls import path
from hospital import views

urlpatterns = [
    path("", views.index, name = 'home'),
    path("login", views.loginUser, name="login"),
    path("logout", views.logoutUser, name="logout"),
     path("login_signup", views.login_signup, name="login_signup"),
     path("mainpage", views.mainpage, name="mainpage"),
    path("signup", views.signup, name="signup")
]
