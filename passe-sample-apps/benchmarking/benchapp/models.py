from django.db import models

# Create your models here.

class Foo(models.Model):
    databar = models.CharField(max_length=20)
