from datetime import datetime
from nis import cat
from operator import indexOf
from xml.dom.minidom import Document
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import logout,login,authenticate,get_user_model
from exceptiongroup import catch
from matplotlib.pyplot import close
from matplotlib.style import use
from numpy import empty
from rsa import PublicKey, sign
from hospital.models import Documents, Patient
import rsa
from django.core.files import File
import phonenumbers
from django.contrib import messages
from .otp import sendOTP
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
                otp = sendOTP(username)
                # print(user)
                return render(request, 'otpVerif.html', {'user':user , 'req' : request, 'realOtp':otp})
                # for patient in Patient.objects.all():
                #     if str(patient.mobile) == username:
                #         return redirect("/patientDashboard")

                # return redirect("/mainpage")
        else:
            return render(request, 'login.html')
    return render(request, 'login.html')

def signup(request):
    return render(request,"signup.html")

def signDocs(file):
    (public,private) = rsa.newkeys(2048)
    with open('privatekey.key','wb') as key_file:
        key_file.write(private.save_pkcs1('PEM'))
    privkey = rsa.PrivateKey.load_pkcs1(open('privatekey.key','rb').read())
    close('privatekey.key')
    # print(privkey)
    # print(private)
    message = open(file,'rb').read()
    close(file)
    signature = rsa.sign(message,private,'SHA-512')
    # verify(message,signature,public)
    return signature,public


# Register new Patient
# Digitally Sign the uploaded identity Document
# Store signature and public key along with doc in Patient model
def validatePhone(phone):
    
    my_number = phonenumbers.parse(phone)
    return phonenumbers.is_possible_number(my_number)

def signupPatient(request):
    userType = request.POST.get("userType")
    if(request.method=="POST" and userType=="Patient"):
        name = request.POST.get("name")
        address = request.POST.get("address")
        email = request.POST.get("email")
        phone = request.POST.get("phone")


        # allUsers = []
        # for user in get_user_model().objects.all():
        #     allUsers.append(user.username)
        # print(allUsers)

        # if(phone in allUsers):
        #     print("Phone number already used, not registered")
        #     messages.warning(request, 'Phone number already used, not registered')
        #     return redirect('signupPatient')

        # if(not validatePhone("+91"+phone)):
        #     print("Phone number Invalid!!, not registered")
        #     messages.warning(request, 'Phone number Invalid!!, not registered')
        #     return redirect('signupPatient')
        # else:
        #     print("valid number")

        dp = request.FILES["dp"]
        aadhar = request.FILES["aadhar"]
        password = request.POST.get("password")
        
        patientUser = User.objects.create_user(str(phone), email, password)
        patientUser.first_name = name
        patientUser.save()
        # print("patient profile picture",type(dp))
        patient = Patient(user=patientUser,identity=aadhar,profile_pic=dp,name=name,email=email,address=address,mobile=phone,userType=userType,dateCreated=datetime.today(),verified=False)
        patient.save()

        #sign the document
        patient = Patient.objects.get(mobile=phone)
        # print(patient.name,"+++++++++++++++++++++++++++",patient.identity)
        
        identitySign,publicKey = signDocs(patient.identity.path)
        

        slash = patient.identity.name.rfind('/')
        dot = patient.identity.name.find('.')
        keyName = "publickey"+str(patient.mobile)+patient.identity.name[slash+1:dot]+".key"
        with open ('static/Patient/Keys/'+keyName,'wb') as key_file:
            key_file.write(publicKey.save_pkcs1('PEM'))
        # signName = "signature_file"+str(patient.mobile)+patient.identity.name[slash+1:dot]
        # s = open('static/Patient/Signatures/'+signName,'wb')
        # s.write(identitySign)
        # print(key_file,s)
        print(type(identitySign))
        patient.identitySign = str(identitySign,'latin-1')#storing signature as string
        patient.publicKey = key_file.name
        patient.save()
        messages.success(request, 'Patient Signed Up Successfully')
        #verifying
        patient = Patient.objects.get(mobile=phone)
        signFile = patient.identitySign

        pubkey = rsa.PublicKey.load_pkcs1(open(patient.publicKey.name,'rb').read())
        doc = open(patient.identity.name,'rb').read()
        close(patient.identity.name)
        close(patient.publicKey.name)
     
        verify(doc,bytes(signFile,'latin-1'),pubkey)
        
    return render(request,'signupPatient.html')

def phoneNumber(request):
    
    if(request.method=="POST" and request.POST.get('phone') is not None):
        phone = request.POST.get('phone')
        allUsers = []
        for user in get_user_model().objects.all():
            allUsers.append(user.username)
            print(allUsers)

        if(phone in allUsers):
            print("Phone number already used, not registered")
            messages.warning(request, 'Phone number already used, not registered')
            return redirect('phoneNumber')

        if(not validatePhone("+91"+phone)):
            print("Phone number Invalid!!, not registered")
            messages.warning(request, 'Phone number Invalid!!, not registered')
            return redirect('phoneNumber')
        else:
            print("Entered phone no is",phone)
            otp = sendOTP(phone)
            print('sent otp is ',otp)
            return render(request,'patientOtp.html',{'phone':phone,'realOtp':str(otp)})
    
    return render(request,'phoneNumber.html')

def patientOtp(request):
    if(request.method=="POST"):
        phone = request.POST.get('phone')
        otp = request.POST.get('otp')
        print("username" , phone)
        print("otp" ,otp)
        if phone is None:
            return redirect('signup')

        else:
            #legit user trying to register lets verify otp
            otp = request.POST.get('otp')
            realOtp = request.POST.get('realOtp')
            # realOtp = otp
            print(realOtp)
            print(otp)
            if(otp==realOtp):
                return render(request,'signupPatient.html',{'phone':phone})
            else:
                messages.warning(request, 'OTP mismatch, enter again')
                logoutUser(request)
                return redirect('patientOtp')
    return render(request,'patientOtp.html')

def verify(doc,signature,pubkey):
    try:
        rsa.verify(doc,signature,pubkey)
        print("Identity digital signature verified")
        return True
    except:
        print("WARNING, Identity could not be verified")
        return False


def signupDoctor(request):
    userType = request.POST.get("userType")
    if(request.method=="POST" and userType=="Doctor"):
        name = request.POST.get("name")
        address = request.POST.get("address")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        dp = request.POST.get("dp")
        password = request.POST.get("password")
        license = request.POST.get("license")
        otherDocs = request.POST.get("other")
        print("Did you try to signup a doctor?")
        # patientUser = User.objects.create_user(str(phone), email, password)
        # patientUser.first_name = name
        # patientUser.save()
        # print(patientUser)
        # patient = Patient(user=patientUser,profile_pic=dp,name=name,email=email,address=address,mobile=phone,userType=userType,dateCreated=datetime.today(),verified=False)
        # print(patientCount+1)
        # patient.save()
        # patientCount+1
    return render(request,'signupDoctor.html')

def logoutUser(request):
    logout(request)
    return redirect("/login")

def getLoggedinPatient(request,context):
    for i in Patient.objects.all():
            if(not request.user.is_anonymous and str(i.mobile)==request.user.username):
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
def getallPatientUsernames():
    list = []
    for p in Patient.objects.values("mobile"):
        list.append(str(p['mobile']))
    return list

def patientUpload(request):
    if request.user.is_anonymous:
        return redirect("/login")
    patientUser = request.user
    allPatients = getallPatientUsernames()

    if(request.method=="POST" and patientUser.username in allPatients):
        id = Documents.objects.all().last().id + 1
        file = request.FILES['patientDoc']
        type = request.POST.get("docType")
        doc = Documents(id=id,file=file,owner=patientUser.username,type=type)
        doc.save()
        doc = Documents.objects.get(id=id)
        sign,pubkey = signDocs(doc.file.path)

        slash = doc.file.name.rfind('/')
        dot = doc.file.name.find('.')
        keyName = "publickey"+patientUser.username+doc.file.name[slash+1:dot]+".key"
        with open ('static/Documents/Keys/'+keyName,'wb') as key_file:
            key_file.write(pubkey.save_pkcs1('PEM'))
        doc.signature = str(sign,'latin-1')#storing signature as string
        doc.publicKey = key_file.name
        doc.save()

    return render(request,'patientUpload.html')

def patientMydocs(request):
    if request.user.is_anonymous:
        return redirect("/login")
    patientUser = request.user
    allPatients = getallPatientUsernames()
    print(request.method)
    context = {
        'fileName' : []
    }
    if(request.method=="GET" and patientUser.username in allPatients):
        print("hiiiii")
        for doc in Documents.objects.filter(owner=patientUser.username):
            slash = doc.file.name.rfind('/')
            fn = doc.file.name[slash+1:]
            tuple=(fn,doc.file.name,doc.id)
            context['fileName'].append(tuple)

    if(request.method=="POST" and patientUser.username in allPatients):
        for keys in request.POST:
            print("Deleting??")
            if(keys=='deleteDoc'):
                id = request.POST[keys]
                docModel = Documents.objects.get(id=id)
                docModel.delete()
        for doc in Documents.objects.filter(owner=patientUser.username):
            slash = doc.file.name.rfind('/')
            fn = doc.file.name[slash+1:]
            tuple=(fn,doc.file.name,doc.id)
            context['fileName'].append(tuple)

    return render(request,'patientMydocs.html',context)


def patientDashboard(request):
    print(request.user)
    context = {
            'loggedinPatient' : 'NULL'
        }
    context = getLoggedinPatient(request,context)

    if request.user.is_anonymous or context['loggedinPatient']=='NULL':
        return redirect("/login")
        
    return render(request, 'patientDashboard.html', context)


def countPatients(request,context):
    context['numPatients'] = Patient.objects.all().count()
    return context

def adminPage(request):
    if request.user.is_anonymous or request.user.is_superuser==0:
        return redirect("/login")
    context = {
            'loggedinPatient' : 'NULL',
            'allUsers' : get_user_model().objects.all().values(),
            'numPatients' : 0
        }
    
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'admin.html',context)

def adminPatient(request):
    if request.user.is_anonymous or request.user.is_superuser==0:
        return redirect("/login")
    if(request.method=="POST"):
        for keys in request.POST:
            if(keys=='verifyPatient'):
                patientUsername = request.POST[keys]
                patientModel = Patient.objects.get(mobile=patientUsername)
                print(patientModel.verified)
                patientModel.verified = True
                patientModel.save()
            if(keys=='deletePatient'):
                patientUsername = request.POST[keys]
                patientModel = Patient.objects.get(mobile=patientUsername)
                patientUser = get_user_model().objects.get(username=patientUsername)
                patientModel.delete()
                patientUser.delete()
            if(keys=='verifyIdentity'):
                patientUsername = request.POST[keys]
                patientModel = Patient.objects.get(mobile=patientUsername)
                signFile = patientModel.identitySign
                pubkey = rsa.PublicKey.load_pkcs1(open(patientModel.publicKey.name,'rb').read())
                doc = open(patientModel.identity.name,'rb').read()
                close(patientModel.identity.name)
                close(patientModel.publicKey.name)
                success = verify(doc,bytes(signFile,'latin-1'),pubkey)
                if(success):
                    patientModel.signVerified = 1
                else:
                    patientModel.signVerified = 2
                patientModel.save()
    # for key in Patient.objects.all().values():
    #     print(key)
    verifyDoc = {'original':'xyz.pdf',
                'signature':'sign',
                'public_key':'pub'
                }
    context = {
            'loggedinPatient' : 'NULL',
            'numPatients' : 0,
            'patientList' : Patient.objects.all().values()
        }
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'adminPatient.html',context)




def otpVerif(request):

    if(request.method=="POST"):
        user = request.POST.get('user')
        otp = request.POST.get('otp')
        print("username" , user)
        print("otp" ,otp)
        if user is None:
            return redirect('login')

        else:
            #legit user lets verify otp
            otp = request.POST.get('otp')
            realOtp = request.POST.get('realOtp')

            print(realOtp)
            print(otp)
            if(otp==realOtp):
                for patient in Patient.objects.all():
                    if str(patient.mobile) == user:
                        return redirect("/patientDashboard")
            else:
                messages.warning(request, 'OTP mismatch, login again')
                logoutUser(request)
                return redirect('login')