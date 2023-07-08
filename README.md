# fcsProject
The website is implemented in Django framework.
This application was developed for a corse project on Computer Security.

User has 3 options to signup as.. patient, doctor or Hospital.. you have to provide documents like licences and identity. Admin will verify the documents.
Once signed up and verified, user has to go through 2-factor verification via OTP sent on registered mobile number. Once verified, you can use the website.
The main task is to facilitate secure exchange of health records between the parties which can be patien-doctors, patients-HealthcareOrganisations and vice versa.
The application also includes a test payment gateway using **razorpay** api for the purpose of buying medicines.

The users can share documents with each other. 
When a document is uploaded, it is digitally signed using RSA-512 algorithm and private key is securely saved at the backend.

The second user can see shared documents and verify the authenticity of the doc by a single button click. If the contents of the document was changed or it was manipulated by any means,
the signature verification will fail as the previously generated key won't decode the newly generated cipher as it was originally generated.

Functionalities include, login/sign-up, 2-factor verification, doc upload, doc deletion, document sharing, Signature verification, Doctors and hospital searching, Buy medicines.
Admin functionalities include : verify user, Removing flag users

This is Patient's dashboard 
![image](https://github.com/ritsiiitd/fcsProject/assets/88946197/ce6bc8b9-69b0-4398-8579-58bd4bcf1fbb)

This is doctor's dashboard 
![image](https://github.com/ritsiiitd/fcsProject/assets/88946197/0a7c9e42-03c2-4596-b4d8-edacf1b7a001)

Document upload page
![image](https://github.com/ritsiiitd/fcsProject/assets/88946197/80170ea9-a84c-4ac9-9472-aa137c7d8b29)

Document sharing
![image](https://github.com/ritsiiitd/fcsProject/assets/88946197/1a68a0fd-0ec9-43fd-ab13-ff4603f3797a)

Document verification
![image](https://github.com/ritsiiitd/fcsProject/assets/88946197/1b266a0e-cb5d-4e58-9f82-c25e04401d78)


A more detailed guide is at : [https://docs.google.com/document/d/1nr1S3D5p5cowGC-av2krKJDHM38MPz0UnDsZU-PC_6Y/edit?usp=sharing](url)
