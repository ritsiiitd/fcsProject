# Generated by Django 4.1.2 on 2022-10-29 21:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospital', '0004_patient_phoneverified'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctor',
            name='other_docs',
        ),
        migrations.AddField(
            model_name='doctor',
            name='identitySign',
            field=models.CharField(max_length=1024, null=True),
        ),
        migrations.AddField(
            model_name='doctor',
            name='phoneVerified',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='doctor',
            name='publicKey',
            field=models.FileField(blank=True, null=True, upload_to='static/Doctor/Keys'),
        ),
        migrations.AddField(
            model_name='doctor',
            name='signVerified',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='doctor',
            name='specialization',
            field=models.CharField(max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='doctor',
            name='license',
            field=models.FileField(blank=True, null=True, upload_to='static/Doctor/License'),
        ),
        migrations.AlterField(
            model_name='doctor',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='static/Doctor/Profile_pics'),
        ),
    ]
