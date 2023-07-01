from django.db import models
from django.contrib.auth.models import AbstractUser




# Create your models here.

class User(AbstractUser):
    name=models.CharField(max_length=255)
    email=models.EmailField(unique=True, max_length=255)
    password=models.CharField(max_length=255)
    username=models.CharField(max_length=255, unique=True)
    
    USERNAME_FIELD='username'
    REQUIRED_FIELD=[]