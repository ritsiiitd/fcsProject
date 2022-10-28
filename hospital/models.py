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
    
    def __Str__(self):
        return self.name


class Doctor(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='static/Doctor/',null=True,blank=True)
    license = models.FileField(upload_to='static/Doctor/',null=True,blank=True)
    other_docs = models.FileField(upload_to='static/Doctor/',null=True,blank=True)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    address = models.CharField(max_length=40,null='False')
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    userType = models.CharField(max_length=10)
    dateCreated = models.DateField()
    verified = models.BooleanField(default=False)

    def __Str__(self):
        return self.name


class Documents(models.Model):
    id = models.IntegerField(primary_key=True,null = False)
    type = models.CharField(max_length=40,default='other')
    file = models.FileField(upload_to='static/Documents/Upload',null=False,blank=True)
    signature = models.CharField(max_length=1024,null=True)
    publicKey = models.FileField(upload_to='static/Documents/Keys',null=True,blank=True)
    owner = models.CharField(max_length=40,null=False)
    sharedWith = models.TextField(null=True)
