# Generated by Django 4.1.2 on 2022-10-31 17:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospital', '0008_hospital_phoneverified_hospital_signverified_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='documents',
            name='sharedWith',
            field=models.TextField(default='[]', null=True),
        ),
    ]
