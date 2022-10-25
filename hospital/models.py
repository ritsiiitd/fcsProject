import email
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Patient(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    profile_pic= models.ImageField(upload_to='static/profile_pic/PatientProfilePic/',null=True,blank=True)
    name = models.CharField(max_length=40,null='False')
    email = models.CharField(max_length=40,default="xyz@gmail.com")
    address = models.CharField(max_length=40,null='False')
    mobile = models.IntegerField(primary_key=True,max_length = 10,null=False)
    userType = models.CharField(max_length=10)
    dateCreated = models.DateField()
    verified = models.BooleanField(default=False)

    def __Str__(self):
        return self.name
