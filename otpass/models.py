from django.db import models

# Create your models here.

class KeyStore(models.Model):
    name = models.CharField(max_length=30, primary_key=True)
    pubkey = models.TextField()
    prikey = models.TextField()

class RequestOtp(models.Model):
    idx = models.AutoField(primary_key=True)
    ipaddr = models.GenericIPAddressField()
    email = models.CharField(max_length=100)
    pwd = models.TextField()
    datetime = models.DateTimeField(auto_now_add=True)
    mail_idx = models.PositiveSmallIntegerField()
    answer = models.TextField()
    
    
class UserPwd(models.Model):
    email = models.CharField(max_length=100, primary_key=True)
    pwd = models.CharField(max_length=3000)
    key_pair = models.ForeignKey("KeyStore", on_delete=models.PROTECT)

