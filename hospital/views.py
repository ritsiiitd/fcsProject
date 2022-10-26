from datetime import datetime
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import logout,login,authenticate,get_user_model
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
            if user.is_superuser == 1:
                return redirect("/adminPage")
            else:
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

def getLoggedinPatient(request,context):
    for i in Patient.objects.all():
            if(str(i.mobile)==request.user.username):
                context['loggedinPatient'] = i
    return context


def mainpage(request):
    # print(request.user)
    if request.user.is_anonymous:
        return redirect("/login")
    else:
        
        context = {
            'loggedinPatient' : 'NULL'
        }
        context = getLoggedinPatient(request,context)
                
    return render(request, 'mainpage.html', context)

def countPatients(request,context):
    context['numPatients'] = Patient.objects.all().count()
    return context

def adminPage(request):
    context = {
            'loggedinPatient' : 'NULL',
            'allUsers' : get_user_model().objects.all().values(),
            'numPatients' : 0
        }
    
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'admin.html',context)

def adminPatient(request):
    if(request.method=="POST"):
        for keys in request.POST:
            print((keys))
            if(keys=='verifyPatient'):
                patientUsername = request.POST[keys]
                patientModel = Patient.objects.get(mobile=patientUsername)
                print(patientModel.verified)
                patientModel.verified = True
                # patientUser = get_user_model().objects.get(username=patientUsername)
                # print(patientUser)
                patientModel.save()
            if(keys=='deletePatient'):
                patientUsername = request.POST[keys]
                patientModel = Patient.objects.get(mobile=patientUsername)
                patientUser = get_user_model().objects.get(username=patientUsername)
                patientModel.delete()
                patientUser.delete()

    context = {
            'loggedinPatient' : 'NULL',
            'numPatients' : 0,
            'patientList' : Patient.objects.all().values()
        }
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'adminPatient.html',context)