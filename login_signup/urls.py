from django.contrib import admin
from django.urls import path
from login_signup import views
urlpatterns = [
    path("", views.index, name = 'login_signup')
]
