# from tkinter.messagebox import NO
from urllib import response
import requests
import random
from django.conf import settings

def sendOTP(phone):
    try:
        otp= random.randint(100000,999999)
        url = f'https://2factor.in/API/V1/{settings.OTP_API}/SMS/{phone}/{otp}/OTP1'
        response = requests.get(url)
        return otp
    except Exception as e:
        return None