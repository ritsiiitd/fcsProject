import email
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.auth.models import User



# Create your models here.
class Patient(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    identity = models.FileField(upload_to='static/Patient/Identity',null=False)
    identitySign = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Patient/Keys',null=True,blank=True)
    profile_pic = models.ImageField(upload_to='static/Patient/Profile_pics',null=True)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    address = models.CharField(max_length=40,null='False')
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    userType = models.CharField(max_length=10)
    dateCreated = models.DateField()
    verified = models.BooleanField(default=False)
    signVerified = models.IntegerField(default=0)
    phoneVerified = models.IntegerField(default=0)
    def __Str__(self):
        return self.name


class Doctor(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='static/Doctor/Profile_pics',null=True,blank=True)
    license = models.FileField(upload_to='static/Doctor/License',null=True,blank=True)
    identitySign = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Doctor/Keys',null=True,blank=True)
    specialization = models.CharField(max_length=40,null=True)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    address = models.CharField(max_length=40,null='False')
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    userType = models.CharField(max_length=10)
    dateCreated = models.DateField()
    verified = models.BooleanField(default=False)
    signVerified = models.IntegerField(default=0)
    phoneVerified = models.IntegerField(default=0)
    def __Str__(self):
        return self.name


class Documents(models.Model):
    id = models.IntegerField(primary_key=True,null = False)
    type = models.CharField(max_length=40,default='other')
    file = models.FileField(upload_to='static/Documents/Upload',null=False,blank=True)
    signature = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Documents/Keys',null=True,blank=True)
    owner = models.CharField(max_length=40,null=False)
    sharedWith = models.TextField(null=True,default="[""]")


class Hospital(models.Model):

    user = models.OneToOneField(User,on_delete=models.CASCADE)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    license = models.FileField(upload_to='static/Hospital/License',null=True,blank=True)
    identitySign = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Hospital/Keys',null=True,blank=True)
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    pic1 = models.ImageField(upload_to='static/Hospital/pics',null=True,blank=True)
    pic2 = models.ImageField(upload_to='static/Hospital/pics',null=True,blank=True)
    accountNumber = models.IntegerField(null=True)
    IFSC = models.CharField(max_length=10,null='False')
    accountHolder = models.CharField(max_length=20,null='False')
    type = models.CharField(max_length=10)
    state = models.CharField(max_length=10)
    city = models.CharField(max_length=20)
    street = models.CharField(max_length=40)
    description = models.CharField(max_length=1000)
    verified = models.BooleanField(default=False)
    signVerified = models.IntegerField(default=0)
    phoneVerified = models.IntegerField(default=0)

class Pharmacy(models.Model):

    user = models.OneToOneField(User,on_delete=models.CASCADE)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    license = models.FileField(upload_to='static/Pharmacy/License',null=True,blank=True)
    identitySign = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Pharmacy/Keys',null=True,blank=True)
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    pic1 = models.ImageField(upload_to='static/Pharmacy/pics',null=True,blank=True)
    pic2 = models.ImageField(upload_to='static/Pharmacy/pics',null=True,blank=True)
    accountNumber = models.IntegerField(null=True)
    IFSC = models.CharField(max_length=10,null='False')
    accountHolder = models.CharField(max_length=20,null='False')
    type = models.CharField(max_length=10)
    state = models.CharField(max_length=10)
    city = models.CharField(max_length=20)
    street = models.CharField(max_length=40)
    description = models.CharField(max_length=1000)
    medicineList = models.TextField(null=True)
    verified = models.BooleanField(default=False)
    signVerified = models.IntegerField(default=0)
    phoneVerified = models.IntegerField(default=0)


class Insurance(models.Model):

    user = models.OneToOneField(User,on_delete=models.CASCADE)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    license = models.FileField(upload_to='static/Insurance/License',null=True,blank=True)
    identitySign = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Insurance/Keys',null=True,blank=True)
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    pic1 = models.ImageField(upload_to='static/Insurance/pics',null=True,blank=True)
    pic2 = models.ImageField(upload_to='static/Insurance/pics',null=True,blank=True)
    # accountNumber = models.IntegerField(primary_key=True,null=True)
    # IFSC = models.CharField(max_length=10,null='False')
    # accountHolder = models.CharField(max_length=20,null='False')
    type = models.CharField(max_length=10)
    state = models.CharField(max_length=10)
    city = models.CharField(max_length=20)
    street = models.CharField(max_length=40)
    description = models.CharField(max_length=1000)
    verified = models.BooleanField(default=False)
    signVerified = models.IntegerField(default=0)
    phoneVerified = models.IntegerField(default=0)

class Payment(models.Model):
    sender = models.CharField(max_length=40)
    receiver = models.CharField(max_length=40)
    amount = models.CharField(max_length=40)
    remarks = models.CharField(max_length=40)
    status = models.BooleanField(default=False)