from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import logout,login,authenticate

#create_user() in signup

# Create your views here.
def index(request):
    return render(request,'login_signup.html')

def login_signup(request):
    print("Clicked login")
    if request.user.is_anonymous:
        return redirect("/login")
    return render(request,'login_signup.html')

def loginUser(request):
    if request.method=="POST":
        #check credentials
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(username,password)
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request,user)
            return redirect("/mainpage")
        else:
            return render(request, 'login.html')
    return render(request, 'login.html')

def logoutUser(request):
    logout(request)
    return redirect("/login")

def mainpage(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login")
    return render(request, 'mainpage.html')