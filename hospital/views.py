from datetime import datetime
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import logout,login,authenticate
from numpy import empty
from hospital.models import Patient
#create_user() in signup
patientCount = 0
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

def signup(request):
    userType = request.POST.get("userType")
    if(request.method=="POST" and userType=="Patient"):
        name = request.POST.get("name")
        address = request.POST.get("address")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        dp = request.POST.get("dp")
        password = request.POST.get("password")
        
        patientUser = User.objects.create_user(str(phone), email, password)
        patientUser.first_name = name
        patientUser.save()
        print(patientUser)
        patient = Patient(user=patientUser,profile_pic=dp,name=name,email=email,address=address,mobile=phone,userType=userType,dateCreated=datetime.today(),verified=False)
        print(patientCount+1)
        patient.save()
        patientCount+1
    return render(request,'signup.html')

def logoutUser(request):
    logout(request)
    return redirect("/login")

def mainpage(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login")
    else:
        print(request.user.name)
    return render(request, 'mainpage.html')