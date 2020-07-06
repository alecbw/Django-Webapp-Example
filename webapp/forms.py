from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model, login, logout, authenticate, get_user
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError, ObjectDoesNotExist, MultipleObjectsReturned
from django import forms
from django.utils import timezone

from datetime import datetime


##################################### ~ Generic Forms ~ ########################################


class GenericForm(forms.Form): # from here https://stackoverflow.com/questions/11667845/object-has-no-attribute-get
    field1 = forms.CharField(label='Enter Text Here', max_length=200)

    def __init__(self, *args, **kwargs):
        super(GenericForm, self).__init__(*args, **kwargs)


class CheckboxForm(forms.Form):
    field1 = forms.CharField(label='Enter URL Here', max_length=200)
    generic_checkbox = forms.BooleanField(label='Raw HTML', required=False)

    def __init__(self, *args, **kwargs):
        super(CheckboxForm, self).__init__(*args, **kwargs)


class ExtendedTextForm(forms.Form):
    field1 = forms.CharField(widget=forms.Textarea, label='Enter Text Here', max_length=20000000)

    def __init__(self, *args, **kwargs):
        super(ExtendedTextForm, self).__init__(*args, **kwargs)


class UploadForm(forms.Form): # TODO
    field1 = forms.CharField(label='Enter Text Here', max_length=200)

    # export = forms.BooleanField(label='Export', required=False)
    def __init__(self, *args, **kwargs):
        super(UploadForm, self).__init__(*args, **kwargs)

##################################### ~ Extension Specific Forms ~ ########################################

"""
Editor's note: it may or may not be an antipattern to have a bunch of duplicate forms for the different views
Up to you which way you go
"""

class ProxyForm(forms.Form):
    field1 = forms.CharField(label='Enter Location:', max_length=200, required=False)

    def __init__(self, *args, **kwargs):
        super(ProxyForm, self).__init__(*args, **kwargs)

class InviteForm(forms.Form):
    field1 = forms.CharField(label='Email:', max_length=200, required=True)

    def __init__(self, *args, **kwargs):
        super(InviteForm, self).__init__(*args, **kwargs)

class SitealizeForm(forms.Form):
    field1 = forms.CharField(label='Enter Company:', max_length=200)

    def __init__(self, *args, **kwargs):
        super(SitealizeForm, self).__init__(*args, **kwargs)


class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254) #help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        fields = ('email', 'password1', 'password2')
