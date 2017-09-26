# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
from django.db import models
from django.utils import timezone

class Post(models.Model):
    switch_name = models.CharField(max_length=100)
    ip_addr = models.CharField(max_length=100)
    mac_addr = models.CharField(max_length=100)
    default_url = models.CharField(max_length=100)


    def __str__(self):
        return self.switch_name