from datetime import datetime
# from http import client
import json
from nis import cat
from operator import indexOf
import re
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseBadRequest
from requests import request
import razorpay
from xml.dom.minidom import Document
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import logout,login,authenticate,get_user_model
from exceptiongroup import catch
from matplotlib.pyplot import close
from matplotlib.style import use
from numpy import empty, size
from rsa import PublicKey, sign
from hospital.models import Doctor, Documents, Hospital, Insurance, Patient, Pharmacy
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
def userType(user):
    pat=[]
    doc=[]
    phar=[]
    for p in Patient.objects.all():
        pat.append(str(p.mobile))
    for d in Doctor.objects.all():
        doc.append(str(d.mobile))
    for ph in Pharmacy.objects.all():
        phar.append(str(ph.mobile))

    if user.username in pat:
        return "patient"
    if user.username in doc:
        return "doctor"
    if user.username in phar:
        return "pharmacy"
def loginUser(request):

    if request.method=="POST" and request.POST.get('username') is not None and request.POST.get('password') is not None:
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

                #
                type=userType(user)
                print("DOCTOR?",user.username)
                if(type=="patient" and not Patient.objects.get(mobile=user.username).verified):
                    messages.warning(request, 'Profile yet to be verified by admin, contact admin at ritick20460@iiitd.ac.in')
                    return redirect("/login")
                if(type=="doctor" and not Doctor.objects.get(mobile=user.username).verified):
                    messages.warning(request, 'Profile yet to be verified by admin, contact admin at ritick20460@iiitd.ac.in')
                    return redirect("/login")
                if(type=="pharmacy" and not Pharmacy.objects.get(mobile=user.username).verified):
                    messages.warning(request, 'Profile yet to be verified by admin, contact admin at ritick20460@iiitd.ac.in')
                    return redirect("/login")
                # otp = 123456
                #

                # print(user)
                return render(request, 'otpVerif.html', {'user':user , 'req' : request, 'realOtp':otp})
                # for patient in Patient.objects.all():
                #     if str(patient.mobile) == username:
                #         return redirect("/patientDashboard")

                # return redirect("/mainpage")
        else:
            messages.warning(request, 'Invalid credentials, please sign up')
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


def signupDoctor(request):
    userType = request.POST.get("userType")
    if(request.method=="POST" and userType=="Doctor"):
        name = request.POST.get("name")
        address = request.POST.get("address")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        dp = request.FILES["dp"]
        license = request.FILES["license"]
        password = request.POST.get("password")
        specialization = request.POST.get("specialization")
        doctorUser = User.objects.create_user(str(phone), email, password)
        doctorUser.first_name = name
        doctorUser.save()

        doctor = Doctor(user=doctorUser,specialization=specialization,license=license,profile_pic=dp,name=name,email=email,address=address,mobile=phone,userType=userType,dateCreated=datetime.today(),verified=False)
        doctor.save()

        #sign the document
        doctor = Doctor.objects.get(mobile=phone)

        identitySign,publicKey = signDocs(doctor.license.path)
        

        slash = doctor.license.name.rfind('/')
        dot = doctor.license.name.find('.')
        keyName = "publickey"+str(doctor.mobile)+doctor.license.name[slash+1:dot]+".key"
        with open ('static/Doctor/Keys/'+keyName,'wb') as key_file:
            key_file.write(publicKey.save_pkcs1('PEM'))
        
        print(type(identitySign))
        doctor.identitySign = str(identitySign,'latin-1')#storing signature(bytes) as string
        doctor.publicKey = key_file.name
        doctor.save()
        messages.success(request, 'Doctor Signed Up Successfully')
        #verifying
        doctor = Doctor.objects.get(mobile=phone)
        signFile = doctor.identitySign

        pubkey = rsa.PublicKey.load_pkcs1(open(doctor.publicKey.name,'rb').read())
        doc = open(doctor.license.name,'rb').read()
        close(doctor.license.name)
        close(doctor.publicKey.name)
     
        verify(doc,bytes(signFile,'latin-1'),pubkey)
        
    return render(request,'signupDoctor.html')

def signupOrganization(request):
    userType = request.POST.get("userType")
    if(request.method=="POST" and userType=="Pharmacy"):
        name = request.POST.get("name")
        city = request.POST.get("city")
        state = request.POST.get("state")
        street = request.POST.get("street")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        dp1 = request.FILES["dp1"]
        dp2 = request.FILES["dp2"]
        medicines=[]
        meds = request.POST.get("Aspirin")
        meds2 = request.POST.get("Avomine")
        meds3 = request.POST.get("Zerodol")
        meds4 = request.POST.get("Yees")
        meds5 = request.POST.get("Oflox")
        meds6 = request.POST.get("Voveran")
        meds7 = request.POST.get("Glycomet")
        meds8 = request.POST.get("Isolazine")
        meds9 = request.POST.get("Naxdom")
        meds10 = request.POST.get("Roseday10")
        if(meds is not None):
            medicines.append(meds)
        if(meds2 is not None):
            medicines.append(meds2)
        if(meds3 is not None):
            medicines.append(meds3)
        if(meds4 is not None):
            medicines.append(meds4)
        if(meds5 is not None):
            medicines.append(meds5)
        if(meds6 is not None):
            medicines.append(meds6)
        if(meds7 is not None):
            medicines.append(meds7)
        if(meds8 is not None):
            medicines.append(meds8)
        if(meds9 is not None):
            medicines.append(meds9)
        if(meds10 is not None):
            medicines.append(meds10)
        
        print("meds",medicines)
        accno = request.POST.get("acc")
        holder = request.POST.get("holder")
        ifsc = request.POST.get("ifsc")

        license = request.FILES["license"]
        password = request.POST.get("password")
        desc = request.POST.get("desc")

        medList = json.dumps(medicines)
        pharmacyUser = User.objects.create_user(str(phone), email, password)
        pharmacyUser.first_name = name
        pharmacyUser.save()

        pharmacy = Pharmacy(user=pharmacyUser,medicineList=medList,description=desc,accountNumber=accno,IFSC=ifsc,accountHolder=holder,license=license,pic1=dp1,pic2=dp2,name=name,email=email,state=state,city=city,street=street,mobile=phone,type=userType,verified=False)
        pharmacy.save()

        # #sign the document
        pharmacy = Pharmacy.objects.get(mobile=phone)

        identitySign,publicKey = signDocs(pharmacy.license.path)
        

        slash = pharmacy.license.name.rfind('/')
        dot = pharmacy.license.name.find('.')
        keyName = "publickey"+str(pharmacy.mobile)+pharmacy.license.name[slash+1:dot]+".key"
        with open ('static/Pharmacy/Keys/'+keyName,'wb') as key_file:
            key_file.write(publicKey.save_pkcs1('PEM'))
        
        print(type(identitySign))
        pharmacy.identitySign = str(identitySign,'latin-1')#storing signature(bytes) as string
        pharmacy.publicKey = key_file.name
        pharmacy.save()
        messages.success(request, 'Pharmacy Signed Up Successfully')
        #verifying
        # pharmacy = Pharmacy.objects.get(mobile=phone)
        # signFile = doctor.identitySign

        # pubkey = rsa.PublicKey.load_pkcs1(open(doctor.publicKey.name,'rb').read())
        # doc = open(doctor.license.name,'rb').read()
        # close(doctor.license.name)
        # close(doctor.publicKey.name)
     
        # verify(doc,bytes(signFile,'latin-1'),pubkey)
    return render(request,'signupOrganization.html')

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

            #
            # otp = 123456
            #

            print('sent otp is ',otp)
            return render(request,'patientOtp.html',{'phone':phone,'realOtp':str(otp)})
    
    return render(request,'phoneNumber.html')

def phoneNumberDoctor(request):
    
    if(request.method=="POST" and request.POST.get('phone') is not None):
        phone = request.POST.get('phone')
        allUsers = []
        for user in get_user_model().objects.all():
            allUsers.append(user.username)
            print(allUsers)

        if(phone in allUsers):
            print("Phone number already used, not registered")
            messages.warning(request, 'Phone number already used, not registered')
            return redirect('phoneNumberDoctor')

        if(not validatePhone("+91"+phone)):
            print("Phone number Invalid!!, not registered")
            messages.warning(request, 'Phone number Invalid!!, not registered')
            return redirect('phoneNumberDoctor')
        else:
            print("Entered phone no is",phone)
            otp = sendOTP(phone)

            #
            # otp = 123456
            #

            print('sent otp is GOING TO DOCTOR OTP',otp)
            return render(request,'doctorOtp.html',{'phone':phone,'realOtp':str(otp)})
    
    return render(request,'phoneNumberDoctor.html')

def phoneNumberOrg(request):
    
    if(request.method=="POST" and request.POST.get('phone') is not None):
        phone = request.POST.get('phone')
        allUsers = []
        for user in get_user_model().objects.all():
            allUsers.append(user.username)
            print(allUsers)

        if(phone in allUsers):
            print("Phone number already used, not registered")
            messages.warning(request, 'Phone number already used, not registered')
            return redirect('phoneNumberOrg')

        if(not validatePhone("+91"+phone)):
            print("Phone number Invalid!!, not registered")
            messages.warning(request, 'Phone number Invalid!!, not registered')
            return redirect('phoneNumberOrg')
        else:
            print("Entered phone no is",phone)
            otp = sendOTP(phone)

            #
            # otp = 123456
            #

            print('sent otp is GOING TO DOCTOR OTP',otp)
            return render(request,'orgOtp.html',{'phone':phone,'realOtp':str(otp)})
    
    return render(request,'phoneNumberOrg.html')



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
            #
            # realOtp = otp
            #
            print(realOtp)
            print(otp)
            if(otp==realOtp):
                return render(request,'signupPatient.html',{'phone':phone})
            else:
                messages.warning(request, 'OTP mismatch, enter again')
                logoutUser(request)
                return redirect('patientOtp')
    return render(request,'patientOtp.html')

def doctorOtp(request):
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
            #
            # realOtp = otp
            #
            print(realOtp)
            print(otp)
            if(otp==realOtp):
                return render(request,'signupDoctor.html',{'phone':phone})
            else:
                messages.warning(request, 'OTP mismatch, enter again')
                logoutUser(request)
                return render(request,'doctorOtp.html')
    return render(request,'doctorOtp.html')

def orgOtp(request):
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
            #
            # realOtp = otp
            #
            print(realOtp)
            print(otp)
            if(otp==realOtp):
                return render(request,'chooseOrg.html',{'phone':phone})
            else:
                messages.warning(request, 'OTP mismatch, enter again')
                logoutUser(request)
                return render(request,'orgOtp.html')
    return render(request,'orgOtp.html')

def chooseOrg(request):
    
    if(request.method=='POST'):
        phone = request.POST.get('phone')
        type = request.POST.get('type')
        return render(request,'signupOrganization.html',{'type':type,'phone':phone})
    return render(request,'chooseOrg.html')

def verify(doc,signature,pubkey):
    try:
        rsa.verify(doc,signature,pubkey)
        print("Identity digital signature verified")
        return True
    except:
        print("WARNING, Identity could not be verified")
        return False


def logoutUser(request):
    logout(request)
    return redirect("/login")

def getLoggedinPatient(request,context):
    for i in Patient.objects.all():
            if(not request.user.is_anonymous and str(i.mobile)==request.user.username):
                context['loggedinPatient'] = i
    return context

def getLoggedinDoctor(request,context):
    for i in Doctor.objects.all():
            if(not request.user.is_anonymous and str(i.mobile)==request.user.username):
                context['loggedinDoctor'] = i
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
def getallDoctorUsernames():
    list = []
    for p in Doctor.objects.values("mobile"):
        list.append(str(p['mobile']))
    return list
def getallPharmacyUsernames():
    list = []
    for p in Pharmacy.objects.values("mobile"):
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


def doctorUpload(request):
    if request.user.is_anonymous:
        return redirect("/login")
    doctorUser = request.user
    allDoctors = getallDoctorUsernames()

    if(request.method=="POST" and doctorUser.username in allDoctors):
        id = Documents.objects.all().last().id + 1
        file = request.FILES['doctorDoc']
        type = request.POST.get("docType")
        doc = Documents(id=id,file=file,owner=doctorUser.username,type=type)
        doc.save()
        doc = Documents.objects.get(id=id)
        sign,pubkey = signDocs(doc.file.path)

        slash = doc.file.name.rfind('/')
        dot = doc.file.name.find('.')
        keyName = "publickey"+doctorUser.username+doc.file.name[slash+1:dot]+".key"
        with open ('static/Documents/Keys/'+keyName,'wb') as key_file:
            key_file.write(pubkey.save_pkcs1('PEM'))
        doc.signature = str(sign,'latin-1')#storing signature as string
        doc.publicKey = key_file.name
        doc.save()

    return render(request,'doctorUpload.html')

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

def doctorMydocs(request):
    if request.user.is_anonymous:
        return redirect("/login")
    doctorUser = request.user
    allDoctors = getallDoctorUsernames()
    print(request.method)
    context = {
        'fileName' : []
    }
    if(request.method=="GET" and doctorUser.username in allDoctors):
        print("hiiiii")
        for doc in Documents.objects.filter(owner=doctorUser.username):
            slash = doc.file.name.rfind('/')
            fn = doc.file.name[slash+1:]
            tuple=(fn,doc.file.name,doc.id)
            context['fileName'].append(tuple)

    if(request.method=="POST" and doctorUser.username in allDoctors):
        for keys in request.POST:
            print("Deleting??")
            if(keys=='deleteDoc'):
                id = request.POST[keys]
                docModel = Documents.objects.get(id=id)
                docModel.delete()
        for doc in Documents.objects.filter(owner=doctorUser.username):
            slash = doc.file.name.rfind('/')
            fn = doc.file.name[slash+1:]
            tuple=(fn,doc.file.name,doc.id)
            context['fileName'].append(tuple)

    return render(request,'doctorMydocs.html',context)


def patientDashboard(request):
    print(request.user)
    context = {
            'loggedinPatient' : 'NULL'
        }
    context = getLoggedinPatient(request,context)

    if request.user.is_anonymous or context['loggedinPatient']=='NULL':
        return redirect("/login")
        
    return render(request, 'patientDashboard.html', context)

def doctorDashboard(request):
    print(request.user)
    context = {
            'loggedinDoctor' : 'NULL'
        }
    context = getLoggedinDoctor(request,context)

    if request.user.is_anonymous or context['loggedinDoctor']=='NULL':
        return redirect("/login")
        
    return render(request, 'doctorDashboard.html', context)

def countPatients(request,context):
    context['numPatients'] = Patient.objects.all().count()
    context['numDoctors'] = Doctor.objects.all().count()
    context['numPharmacy'] = Pharmacy.objects.all().count()
    return context

def adminPage(request):
    if request.user.is_anonymous or request.user.is_superuser==0:
        return redirect("/login")
    context = {
            'loggedinPatient' : 'NULL',
            'allUsers' : get_user_model().objects.all().values(),
            'numPatients' : 0,
            'numDoctors' : 0,
            'numPharmacy' : 0
        }
    
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    print(context)
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


def adminDoctor(request):
    if request.user.is_anonymous or request.user.is_superuser==0:
        return redirect("/login")
    if(request.method=="POST"):
        for keys in request.POST:
            if(keys=='verifyDoctor'):
                patientUsername = request.POST[keys]
                patientModel = Doctor.objects.get(mobile=patientUsername)
                print(patientModel.verified)
                patientModel.verified = True
                patientModel.save()
            if(keys=='deleteDoctor'):
                patientUsername = request.POST[keys]
                patientModel = Doctor.objects.get(mobile=patientUsername)
                patientUser = get_user_model().objects.get(username=patientUsername)
                patientModel.delete()
                patientUser.delete()
            if(keys=='verifyLicense'):
                patientUsername = request.POST[keys]
                patientModel = Doctor.objects.get(mobile=patientUsername)
                signFile = patientModel.identitySign
                pubkey = rsa.PublicKey.load_pkcs1(open(patientModel.publicKey.name,'rb').read())
                doc = open(patientModel.license.name,'rb').read()
                close(patientModel.license.name)
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
            'numDoctors' : 0,
            'numPharmacy' : 0,
            'doctorList' : Doctor.objects.all().values()
        }
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'adminDoctor.html',context)

def adminPharmacy(request):
    if request.user.is_anonymous or request.user.is_superuser==0:
        return redirect("/login")
    if(request.method=="POST"):
        for keys in request.POST:
            if(keys=='verifyPharmacy'):
                patientUsername = request.POST[keys]
                patientModel = Pharmacy.objects.get(mobile=patientUsername)
                print(patientModel.verified)
                patientModel.verified = True
                patientModel.save()
            if(keys=='deletePharmacy'):
                patientUsername = request.POST[keys]
                patientModel = Pharmacy.objects.get(mobile=patientUsername)
                patientUser = get_user_model().objects.get(username=patientUsername)
                patientModel.delete()
                patientUser.delete()
            if(keys=='verifyLicense'):
                patientUsername = request.POST[keys]
                patientModel = Pharmacy.objects.get(mobile=patientUsername)
                signFile = patientModel.identitySign
                pubkey = rsa.PublicKey.load_pkcs1(open(patientModel.publicKey.name,'rb').read())
                doc = open(patientModel.license.name,'rb').read()
                close(patientModel.license.name)
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
            'numDoctors' : 0,
            'numPharmacy' : 0,
            'pharmacyList' : Pharmacy.objects.all().values()
        }
    context = countPatients(request,context)
    context = getLoggedinPatient(request,context)
    
    return render(request,'adminPharmacy.html',context)





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
            #
            # realOtp = otp
            #
            print(realOtp)
            print(otp)
            
            if(otp==realOtp and user in getallPatientUsernames()):
                for patient in Patient.objects.all():
                    if str(patient.mobile) == user:
                        return redirect("/patientDashboard")
            elif(otp==realOtp and user in getallDoctorUsernames()):
                print("doctor logged in")
                for doctor in Doctor.objects.all():
                    if str(doctor.mobile) == user:
                        return redirect("/doctorDashboard")
            elif(otp==realOtp and user in getallPharmacyUsernames()):
                print("doctor logged in")
                for pharmacy in Pharmacy.objects.all():
                    if str(pharmacy.mobile) == user:
                        return redirect("/pharmacyDashboard")
            else:
                messages.warning(request, 'OTP mismatch, login again')
                logoutUser(request)
                return redirect('login')

def editPatient(request):
    print(request.user)
    context = {
            'loggedinPatient' : 'NULL'
        }
    context = getLoggedinPatient(request,context)

    if request.user.is_anonymous or context['loggedinPatient']=='NULL':
        return redirect("/login")

    elif(request.method=="POST"):

        address = request.POST.get("address")
        email = request.POST.get("email")
        dp = request.FILES.get("dp")

        password = request.POST.get("password")
        patient = Patient.objects.get(mobile=int(request.user.username))

        print(patient)

        if(len(address) !=0):
            patient.address = address
        
        if(len(email)!=0):
            patient.email = email
        
        if(dp is not None):
            patient.profile_pic = dp
        
        if(len(password)!=0):
            puser = get_user_model().objects.get(username=request.user.username)
            puser.set_password(password)
            puser.save()
        
        patient.save()
        messages.success(request, 'Profile updated')

    return render(request, 'editPatient.html', context)



def fillContext(request,context):
    list = []
    for user in get_user_model().objects.all():
        list.append(user)
    context['allUsers'] = list

    list = []
    for user in Patient.objects.all():
        list.append(user)
    context['allPatients'] = list

    list = []
    for user in Doctor.objects.all():
        list.append(user)
    context['allDoctors'] = list

    list = []
    for user in Hospital.objects.all():
        list.append(user)
    context['allHospital'] = list
    
    list = []
    for user in Pharmacy.objects.all():
        list.append(user)
    context['allPharmacy'] = list

    list = []
    for user in Insurance.objects.all():
        list.append(user)
    context['allInsurance'] = list

    list = []
    for user in Documents.objects.all():
        list.append(user)
    context['allDocs'] = list

    list = []
    for doc in Documents.objects.filter(owner=request.user.username):
        slash = doc.file.name.rfind('/')
        fn = doc.file.name[slash+1:]
        jsonDec = json.decoder.JSONDecoder()
        print(doc.sharedWith)
        sharedWith = []
        if(doc.sharedWith is not None):
            sharedWith = jsonDec.decode(doc.sharedWith)

        # print(type(sharedWith[0]))
        intShared = []
        for d in sharedWith:
            intShared.append(int(d))
        # print(type(intShared[0]))
        tuple = (fn,doc,doc.type,doc.id,intShared)
        list.append(tuple)
    context['myDocs'] = list

    # print(context)
    return context


###############
def patientShare(request):

    context = {
            'loggedinPatient' : 'NULL',
            'allUsers' : 'NULL',
            'allDoctors' : 'NULL', 
            'allPatients' : 'NULL', 
            'allHospital' : 'NULL',
            'allPharmacy' : 'NULL',
            'allInsurance' : 'NULL',
            'allDocs' : 'NULL',
            'myDocs' : 'NULL'
        }
    context = getLoggedinPatient(request,context)
    context = fillContext(request,context)
    if request.user.is_anonymous or context['loggedinPatient']=='NULL':
        return redirect("/login")
    print(len(request.GET))
    if(request.method=="GET" and len(request.GET)>1):
        #we got some users to add in share with of given doc
        share = (request.GET)
        # print(share)
        di = dict(share)
        if len(request.GET)<3:
            sharedwith = []
        else:
            sharedwith = di['doctor']
        docId = di['documentID'][0]
        # print(docId)
        document = Documents.objects.get(id=docId)
        
        # print(type(sharedwith),sharedwith)
        
        jsonDec = json.decoder.JSONDecoder()
        sharedWithORG = []
        if(document.sharedWith is not None):
            sharedWithORG = jsonDec.decode(document.sharedWith)
        
        for rem in Doctor.objects.all():
            print(rem,"+++++++",sharedwith)
            if str(rem.mobile) not in sharedwith and str(rem.mobile) in sharedWithORG:
                print("remo",rem)
                sharedWithORG.remove(str(rem.mobile))
        
        for i in sharedWithORG:
            sharedwith.append(i)
        sharedwith=[*set(sharedwith)]
        # sharedwith = sharedwith.extend(sharedWithORG)
        document.sharedWith = json.dumps(sharedwith)
        document.save()
        messages.success(request, 'Shared!!')
    context = getLoggedinPatient(request,context)
    context = fillContext(request,context)
   
    return render(request, 'patientShare.html', context)

def patientShare2(request):

    context = {
            'loggedinPatient' : 'NULL',
            'allUsers' : 'NULL',
            'allDoctors' : 'NULL', 
            'allPatients' : 'NULL', 
            'allHospital' : 'NULL',
            'allPharmacy' : 'NULL',
            'allInsurance' : 'NULL',
            'allDocs' : 'NULL',
            'myDocs' : 'NULL'
        }
    context = getLoggedinPatient(request,context)
    context = fillContext(request,context)
    if request.user.is_anonymous or context['loggedinPatient']=='NULL':
        return redirect("/login")
    print(len(request.GET))
    if(request.method=="GET" and len(request.GET)>1):
        #we got some users to add in share with of given doc
        share = (request.GET)
        # print(share)
        di = dict(share)
        if len(request.GET)<3:
            sharedwith = []
        else:
            sharedwith = di['pharma']
        docId = di['documentID'][0]
        # print(docId)
        document = Documents.objects.get(id=docId)
        
        # print(type(sharedwith),sharedwith)
        
        jsonDec = json.decoder.JSONDecoder()
        sharedWithORG = []
        if(document.sharedWith is not None):
            sharedWithORG = jsonDec.decode(document.sharedWith)
        
        for rem in Pharmacy.objects.all():
            print(rem,"+++++++",sharedwith)
            if str(rem.mobile) not in sharedwith and str(rem.mobile) in sharedWithORG:
                print("remo",rem)
                sharedWithORG.remove(str(rem.mobile))
        
        for i in sharedWithORG:
            sharedwith.append(i)
        sharedwith=[*set(sharedwith)]
        # sharedwith = sharedwith.extend(sharedWithORG)
        document.sharedWith = json.dumps(sharedwith)
        document.save()
        messages.success(request, 'Shared!!')
    context = getLoggedinPatient(request,context)
    context = fillContext(request,context)
    
    return render(request, 'patientShare2.html', context)

def buyMeds(request):
    return render(request,"choosePharmacy.html",{"allPharmacy":Pharmacy.objects.all()})

def choosePharmacy(request):
    if(request.method=="POST"):
        phone = request.POST.get('phone')
        pharmacy = Pharmacy.objects.get(mobile=int(phone))
        jsonDec = json.decoder.JSONDecoder()
        meds = []
        if(pharmacy.medicineList is not None):

            meds = jsonDec.decode(pharmacy.medicineList)
        med_price = []
        for m in meds:
            both =  m.split(',')
            both[1] = both[1][4:]
            med_price.append(both)
            print(med_price)
        return render(request,"chooseMeds.html",{'pharmacy':pharmacy,'med_price':med_price})
    return render(request,"choosePharmacy.html",{"allPharmacy":Pharmacy.objects.all()})

razorpay_client = razorpay.Client(auth=("rzp_test_IsrxZBkSBR9sDD", "stJEcY9Fy6dKy3RUpTTPD8s8"))

# CREDITS = https://www.geeksforgeeks.org/razorpay-integration-in-django/


def chooseMeds(request):
    # if(request.method=="POST"):
    if(request.method=="POST"):
        price = request.POST.get('price')
        print(price)
        currency = 'INR'
        amount = 20000  # Rs. 200
    
        # Create a Razorpay Order
        razorpay_order = razorpay_client.order.create(dict(amount=amount,
                                                        currency=currency,
                                                        payment_capture='0'))
    
        # order id of newly created order.
        razorpay_order_id = razorpay_order['id']
        callback_url = 'paymenthandler'
    
        # we need to pass these details to frontend.
        context = {}
        context['order_id'] = razorpay_order_id
        context['key'] = 'rzp_test_IsrxZBkSBR9sDD'
        context['amount'] = amount
        context['currency'] = currency
        context['callback_url'] = callback_url
        print(razorpay_order_id)
        return render(request, 'razorpay.html', context=context)
        return render(request,"razorpay.html")
    return render(request,"chooseMeds.html")

def razorpay(request):
    
    print("I was here")
    return render(request, 'razorpay.html')


@csrf_exempt
def paymenthandler(request):
    print("payment was done??")
    # only accept POST request.
    if request.method == "POST":
        try:
            # print(request.POST)
            # get the required parameters from post request.
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }
            print(params_dict)
            # verify the payment signature.
            result = razorpay_client.utility.verify_payment_signature(params_dict)
            if result is not None:
                amount = 20000  # Rs. 200
                try:
 
                    # capture the payemt
                    print("payment? captured?")
                    razorpay_client.payment.capture(payment_id, amount)
                    
 
                    # render success page on successful caputre of payment
                    return render(request, 'paitentDashboard.html')
                except:
 
                    # if there is an error while capturing payment.
                    print("payment? fail?")
                    return render(request, 'paymentfail.html')
            else:
 
                # if signature verification fails.
                print("payment? fail? not POST")
                return render(request, 'paymentfail.html')
        except:
 
            # if we don't find the required parameters in POST data
            return HttpResponseBadRequest()
    else:
       # if other than POST request is made.
        return HttpResponseBadRequest()