from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class UserCredentials(models.Model):
	user = models.ForeignKey(User)
	token_cloud = models.CharField(max_length=150)
	secret_cloud = models.CharField(max_length=150, null=True)
	token_kanal = models.CharField(max_length=150)
	last = models.TextField()
	
class Channel(models.Model):
	user = models.ForeignKey(User)
	name = models.CharField(max_length=100)

class Item(models.Model):
	canal = models.ForeignKey(Channel)
	full_path = models.CharField(max_length=400)
	nome = models.CharField(max_length=100)