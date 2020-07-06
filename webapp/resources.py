from django.contrib.auth.models import User
from tastypie import fields
from tastypie.resources import ModelResource
# from tastypie.authorization import Authorization
from tastypie.authorization import DjangoAuthorization
from tastypie.authentication import BasicAuthentication, ApiKeyAuthentication, MultiAuthentication
from import_export import resources
from .models import APIKey, Product, Person

class UserResource(ModelResource): # for Tastypie
    class Meta:
        queryset = User.objects.all()
        resource_name = 'user'
        excludes = ['email', 'password', 'is_active', 'is_staff', 'is_superuser', "date_joined", "first_name", "last_name", "username", "last_login"]
        allowed_methods = ['get']
    # Maps `Entry.user` to a Tastypie `ForeignKey` field named `user`,
    # which gets serialized using `UserResource`. The first appearance of
    # 'user' on the next line of code is the Tastypie field name, the 2nd
    # appearance tells the `ForeignKey` it maps to the `user` attribute of
    # `Entry`. Field names and model attributes don't have to be the same.

class ProductResource(ModelResource): # Tastypie API
    class Meta:
        user = fields.ForeignKey(UserResource, 'user')
        # model = Product
        queryset = Product.objects.all()
        resource_name = 'products'
        authorization = DjangoAuthorization()
        authentication = MultiAuthentication(ApiKeyAuthentication(), BasicAuthentication())
        # user_ip =

class PersonResource(resources.ModelResource): # Import-Export for CSVs
    class Meta:
        model = Person

# class ProductResource(resources.ModelResource): # Import-Export for CSVs
#     class Meta:
#         model = Product
