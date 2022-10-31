from django.contrib import admin
from django.urls import path
from hospital import views

urlpatterns = [
    path("", views.index, name = 'home'),
    path("login", views.loginUser, name="login"),
    path("logout", views.logoutUser, name="logout"),
    path("login_signup", views.login_signup, name="login_signup"),
    path("mainpage", views.mainpage, name="mainpage"),
    path("signup", views.signup, name="signup"),
    path("signupDoctor", views.signupDoctor, name="signupDoctor"),
    path("signupPatient", views.signupPatient, name="signupPatient"),
    path("signupOrganization", views.signupOrganization, name="signupOrganization"),
    path("adminPage", views.adminPage, name="adminPage"),
    path("adminPatient", views.adminPatient, name="adminPatient"),
    path("adminPharmacy", views.adminPharmacy, name="adminPharmacy"),
    path("adminDoctor", views.adminDoctor, name="adminDoctor"),
    path("patientDashboard", views.patientDashboard, name="patientDashboard"),
    path("doctorDashboard", views.doctorDashboard, name="doctorDashboard"),
    path("patientUpload", views.patientUpload, name="patientUpload"),
    path("doctorUpload", views.doctorUpload, name="doctorUpload"),
    path("patientMydocs", views.patientMydocs, name="patientMydocs"),
    path("doctorMydocs", views.doctorMydocs, name="doctorMydocs"),
    path("otpVerif", views.otpVerif, name="otpVerif"),
    path("phoneNumber", views.phoneNumber, name="phoneNumber"),
    path("phoneNumberDoctor", views.phoneNumberDoctor, name="phoneNumberDoctor"),
    path("phoneNumberOrg", views.phoneNumberOrg, name="phoneNumberOrg"),
    path("doctorOtp", views.doctorOtp, name="doctorOtp"),
    path("patientOtp", views.patientOtp, name="patientOtp"),
    path("orgOtp", views.orgOtp, name="orgOtp"),
    path("editPatient", views.editPatient, name="editPatient"),
    path("chooseOrg", views.chooseOrg, name="chooseOrg")

]
