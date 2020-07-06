# pylint: disable=C0326

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class APIKey(models.Model):

    user       = models.ForeignKey(User, null=True, related_name='api_keys', on_delete=models.CASCADE)
    key_name   = models.TextField(max_length=100)
    category   = models.TextField(max_length=30)
    api_key    = models.TextField(max_length=100, unique=True)
    call_count = models.IntegerField()
    is_admin   = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_last  = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self): # This is what you get if you print APIKey.objects.all(). Also in the admin console.
        return '%s - %s - %s' % (self.user, self.key_name, self.category)


class Product(models.Model):

    name               = models.TextField(max_length=50)
    subsite            = models.URLField(null=True, blank=True)
    description        = models.TextField(max_length=500, null=True)
    short_description  = models.TextField(max_length=100, null=True)
    category           = models.TextField(max_length=30)
    individual         = models.BooleanField(default=False)
    iterative          = models.BooleanField(default=False)
    development_status = models.TextField(max_length=30, null=True, blank=True)
    pricing            = models.IntegerField()
    permitted_keys     = models.ManyToManyField(APIKey)
    total_calls        = models.IntegerField()
    created_at         = models.DateTimeField(auto_now_add=True) # Auto_now_add is NOT mutable # TODO PROPER TIMEZONE
    used_last          = models.DateTimeField(auto_now=True)

    def __str__(self): # This is what you get if you print Product.objects.all(). Also in the admin console.
        return '%s - %s - %s' % (self.name, self.short_description, self.development_status)

# App and product telemetry
class UserAction(models.Model):

    SEVERITY_CHOICES = (                                                        #  Choices should always a tuple of tuples, named in all caps
        ('L', 'Logging'),
        ('T2', 'Informational'),
        ('T1', 'Severe'),
        ('T0', 'Pager Duty'))

    user            = models.ForeignKey(User, null=True, related_name='actions', on_delete=models.CASCADE)
    is_admin        = models.BooleanField(default=False)
    action_type     = models.TextField(max_length=100)
    action_severity = models.TextField(max_length=25, choices=SEVERITY_CHOICES, default='Logging')
    product         = models.ForeignKey(Product, null=True, related_name='actions', on_delete=models.CASCADE)
    category        = models.TextField(max_length=30)
    source          = models.TextField(max_length=50, blank=True)
    updated_at      = models.DateTimeField(default=timezone.now)
    ip_address      = models.GenericIPAddressField(null=True, blank=True)
    header          = models.TextField(max_length=200, null=True, blank=True)

    def __str__(self): # This is what you get if you print UserAction.objects.all(). Also in the admin console.
        return '%s - %s - %s - %s' % (self.user, self.product, self.ip_address, self.updated_at)

# To build blacklisted and whitelisted IPs
class IPList(models.Model):

    COLOR_CHOICES = (
        ('U', 'User'),
        ('W', 'Whitelist'),
        ('B', 'Blacklist'),
        ('M', 'Monitor'))

    ip_address      = models.GenericIPAddressField(null=True, blank=True)
    user            = models.ForeignKey(User, null=True, related_name='ip_lists', on_delete=models.CASCADE)
    action_type     = models.TextField(max_length=100)
    list_color      = models.TextField(max_length=25, choices=COLOR_CHOICES, default='Monitor')
    first_detected  = models.DateField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)

    def __str__(self): # This is what you get if you print IPList.objects.all(). Also in the admin console.
        return '%s - %s - %s - %s' % (self.user, self.ip_address, self.list_color, self.first_detected)

class PreapprovedUser(models.Model):
    username           = models.TextField(max_length=50, default='ThisIsAHolderString')
    email              = models.TextField(max_length=50, default="EasterEgg109@contextify.io")
    created_at         = models.DateTimeField(auto_now_add=True) # Auto_now_add is NOT mutable # TODO PROPER TIMEZONE
    source             = models.TextField(max_length=50, null=True, blank=True)

    def __str__(self): # This is what you get if you print PreapprovedUser.objects.all(). Also in the admin console.
      return '%s - %s - %s' % (self.username, self.email, self.created_at)
