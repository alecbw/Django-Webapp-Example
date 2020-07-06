# -*- coding: utf-8 -*-
# pylint: disable=C0103
# pylint: disable=C0111
# pylint: disable=C0301
# pylint: disable=W0311

from __future__ import absolute_import, unicode_literals # Absolute imports are the default in Python 3 so you don’t need this if you target that version. TODO
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import pre_save, pre_init
from django.dispatch import receiver
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.db.models import F
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.core.validators import URLValidator

from celery import shared_task, signature, task
from celery.decorators import periodic_task
from celery.task.control import inspect
from celery.task.schedules import crontab
from celery.result import AsyncResult, ResultBase

from .celery import app
from .models import Product, UserAction, APIKey
from .extensions import Later_Textly_API

from urllib3.exceptions import MaxRetryError, ProtocolError
from requests.exceptions import ProxyError, ConnectionError, HTTPError, SSLError, Timeout
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from time import sleep
from tablib import Dataset
from pprint import pprint
from bs4 import BeautifulSoup
from itertools import cycle
from gevent import pool
import pandas as pd
import chardet
import gspread
import gevent
import requests
import random
import string
import csv
import io
import os
import redis
import re




##################################### ~ Pure Helper Fxns ~ ########################################
# This function is intentionally broken for testing
@shared_task(name="Test_Foo", bind=True)
def test_foo(inputString):
    foo()

def init_var(inputNumber, inputType):
    ref_dict = {"list": [], "str": "", "dict": {}}
    return (ref_dict[inputType] for i in range(inputNumber))

def has_letters(inputString):                      # Detects if there are letters
    return any(c.isalpha() for c in inputString)

def has_numbers(inputString):                      # Detects if there are numbers
    return any(c.isdigit() for c in inputString)

def extract_numbers(inputString):
    return [int(s) for s in inputString.split() if s.isdigit()]

def detect_strings(inputQuery, inputStringsToDetectList):
    return any(substring in inputQuery for substring in inputStringsToDetectList)

def df_missing_values(x):
    return sum(x.isnull())

def detect_link(inputString):
    Generic_TLD_List = ['.com', '.org', '.edu', '.gov', '.uk', '.net', '.ca', '.de', '.jp', '.fr', '.au', '.us', '.ru', '.ch', '.it', '.nl', '.se', '.no', '.es', '.mil', '.io', '.ai', '.co', '.biz', '.info', '.vc', '.tv']

    if not isinstance(inputString, str):
        print(f'Input string {inputString} is type: {type(inputString)}')
        return False

    if detect_strings(inputString.strip(), Generic_TLD_List):
        return True
    else:
        return False

def compare_list_overlap(inputList1, inputList2):
    return list(set(inputList1).intersection(inputList2))

def get_dict_item_by_substring(inputSubString, inputDict):
    results = [value for key, value in inputDict.items() if inputSubString.title() in key.title()]
    if len(results) == 1:
        return results[0]
    elif len(results) > 1:
        return " + ".join(results)
    else:
        print("!!!! Substring not found !!!!")
        return None

def drop_empty_values(inputDict):
    empty_keys = [k for k, v in inputDict.items() if not v]
    output_dict = {k: v for k, v in inputDict.items() if v is not None}

    return output_dict, empty_keys

def modify_keys(inputDict, inputKeyChange):
    new_dict = {inputKeyChange: v for k, v in inputDict.items()}
    return new_dict

def invert_keys_and_values(inputDict):
    inv_map = {v: k for k, v in inputDict.items()}
    return inv_map

def format_timestamp(inputTimeStamp):
    try:
        TimeStamp = (datetime.utcfromtimestamp(float(inputTimeStamp)))
    except ValueError:
        TimeStamp = datetime.strptime(inputTimeStamp,'%Y-%m-%dT%H:%M:%SZ')

    TimeStamp = TimeStamp + timedelta(hours=-8)                      # PDT. Note PST is 8 hours
    TimeStampStr = datetime.strftime(TimeStamp, '%Y-%m-%d %H:%M:%S')

    return TimeStampStr, TimeStamp

# e.g.  deep_get(response, 'data.locations.some_key')
def deep_get(inputObject, path, default=None):  # Get a value from obj using the defined (dot-separated) path.
    keys = path.split('.')

    for key in keys:
        try:                                                  # try as an object
            inputObject = getattr(inputObject, key)
            continue
        except (AttributeError, TypeError):
            pass

        try:                                                     # try as a dict
            inputObject = inputObject.get(key)
            continue
        except AttributeError:
            pass

        try:
            key = int(key)
        except ValueError:
            pass

        try:                                                     # try as a list
            inputObject = inputObject[key]
            continue
        except (AttributeError, TypeError, IndexError):
            pass

    return inputObject or default


##################################### ~ Pure Views & Modules Fxns ~ ########################################


def get_product_h3(request):
    path_info = request.META['PATH_INFO'].replace("/", "")
    try:
        output = Product.objects.get(name__icontains=path_info)
        return f'{output.name} - {output.short_description}'

    except ObjectDoesNotExist:
        admin_pager_duty(request, User.objects.get(username=request.user.username), 'Get_Product_H3 is broken in tasks.py -> ' + path_info)
        return ""


def count_form_entries(inputList, inputCutoff):
    if inputList and isinstance(inputList, str): # If form, rather than file
        outputList = inputList.split(", ")
    elif isinstance(inputList, list):
        outputList = inputList

    if len(outputList) >= inputCutoff:
        return [outputList, True]
    else:
        return [outputList, False]


def output_checkmarks(inputDict):
    for k, v in inputDict.items():
        if isinstance(v, list):
            for n, item in enumerate(v):
                if item == True:
                    v[n] = "&#10004;"
                elif item == False:
                    v[n] = '&times;'

        elif isinstance(v, bool):
            if v == True:
                inputDict[k] = "&#10004;"
            elif v == False:
                inputDict[k] = '&times;'

    return inputDict


def href_all_links(inputDict):
    for k, v in inputDict.items():
        if isinstance(v, list):
            for n, item in enumerate(v):
                if detect_link(item):
                    v[n] = get_href(item, None)

        elif isinstance(v, str) and detect_link(v):
            inputDict[k] = get_href(v, None)

    return inputDict


def get_href(inputLink, inputName):
    if "://" in inputLink:
        inputLink = inputLink.split("://", 1)[1]
    if "www." in inputLink:
        inputLink = inputLink.split("www.", 1)[1]

    prefix_link = f'https://www.{inputLink}'
    if inputName:
        output_href = f'<a href={prefix_link}>{inputName}</a>'
    else:
        output_href = f'<a href={prefix_link}>{inputLink}</a>'

    return output_href


def clean_url_string(inputURL, optionalRemoveTLD): # Formatting to use domain as part of the filename for outputfilecsv
    if not isinstance(inputURL, str):
        inputURL = str(inputURL)

    if "://" in inputURL:
        inputURL = inputURL.split("://", 1)[1]
    if "www." in inputURL:
        inputURL = inputURL.split("www.", 1)[1]
    if "/" in inputURL:
        inputURL = inputURL.split("/", 1)[0]

    if optionalRemoveTLD and "." in inputURL:
        period_location = inputURL.rfind(".")   # Find location of right most period
        inputURL = inputURL[:period_location]   # Slice by that location

    return inputURL


# TODO this tends to cause hangs when used. May need to explore other methods
def retryer(func):
    retry_on_exceptions = (
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.HTTPError,
    )
    max_retries = 1
    timeout = 10

    def inner(*args, **kwargs):
        for _ in range(max_retries):
            try:
                result = func(*args, **kwargs)
            except retry_on_exceptions:
                print("!  IOError  !") # - The program will now attempt to reconnect in 10 seconds
                # sleep(timeout)
                continue
            else:
                return result
        else:
            print('NetworkError')

    return inner


def regex_email(inputEmail):
    output = {}
    Generic_Username_List = ['info', 'sales', 'inquiries', 'contact', 'hello', 'billing', 'help', 'owner', 'support', 'training', 'webmaster', 'admin', 'registrar', 'customers', 'members', 'manager', 'signup']
    Generic_Mailbox_List = ['gmail.com', 'yahoo.com', 'aol.com', 'outlook.com', 'msn.com', 'comcast.net', 'charter.net', 'hotmail.com', 'att.net', 'live.com', 'verizon.net', 'hotmail.ca', 'cox.net', 'ymail.com', 'rocketmail.com', 'googlegroups.com']

    if not inputEmail:
        print ('You entered an empty inputEmail')
        return None

    username = re.findall("([^@]+)", inputEmail)[0]
    if any(substring in username for substring in Generic_Username_List):
        output['username'] = 'generic'

    domain = re.findall("(?<=@)(.*)", inputEmail)[0]
    if any(substring in domain for substring in Generic_Mailbox_List):
        output['mailbox'] = 'generic'

    output['domain'] = domain
    return output


##################################### ~ User Functions ~ ####################################


def get_user_email(inputRequest): # Return the user's email, if it's a valid user
    if not isinstance(inputRequest, str):
        inputRequest = inputRequest.user.username

    try:
        user = User.objects.get(username=inputRequest)
        return user.email
    except ObjectDoesNotExist:
        print( '! No such user to get email for !')
        return None


def get_client_ip(request): # Return the client's ip address. TODO on explanation
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0]
        else:
            client_ip = request.META.get('REMOTE_ADDR')
        return client_ip


def get_client_header(request):
    if request:
        return str(request.META.get('HTTP_USER_AGENT'))


def get_product(request):
    output_dict = {'Source': None, 'Product': None}
    if request:
        path = request.META.get('PATH_INFO')
        output_dict['Source'] = path
        output_dict['Product'] = Product.objects.get(name__iexact=path.replace("/", ""))

    return output_dict


def iterate_call_count(inputProduct):
    if isinstance(inputProduct, str):
        product = Product.objects.get(name__iexact=inputProduct)
    else:
        product = Product.objects.get(id=inputProduct.id)

    product.total_calls = F('total_calls') + 1
    product.save()


def format_useraction_dict(request, user, inputAction, inputProduct):
    if not user: #ToDo
        if user and request.user.is_authenticated:                              # Get User object if logged in
            user = User.objects.get(username=request.user.get_username())
        else:                                                                   # Use a holder User object if noone is logged in
            user = User.objects.get(username='NullUser')

    useraction_dict = {
        'user': user,                                                           # Note: an instance of the User model, NOT the username
        'is_admin': user.is_superuser,                                          # Boolean. Default is False.
        'action_type': inputAction,                                             # Plain text, passed in by the fxn
        'action_severity': "Logging",                                           # Default "Logging". Choice of 4 options. 'Pager duty' is T0 in shorthand.
        'product': Product.objects.get(name__iexact=inputProduct) if inputProduct else Product.objects.get(name="Holder"),                    # Delineates this as initiated by the Reciever function of Django Signals
        'category': "Holding",                                                  # An arbitrary holder value in Product. Similar to above, but more general. Inconsequential except for filtering these out in subsequent SQL fxns and programmatic displays
        'source': request.META.get('PATH_INFO') if request else 'Non-request signal',    # Pulls what subsite was this triggered on
        'ip_address': get_client_ip(request) if request else "0.0.0.0",                  # Pulls client's ip address.
        'header': get_client_header(request) if request else "None"                      # Pulls client's header, which may contain info about if it's a spider or not.
    }

    return useraction_dict


def format_useraction_email(request, inputUADict):
    user_name = inputUADict['user'].username if inputUADict['user'] else "NullUser"

    email_body = (str(datetime.now()) + "\n" +          # Here we format the text that will be sent in the body of the email
                 inputUADict['action_type'] + "\n" +    # Body
                 user_name + "\n")                      # Body

    if request:
        email_body += (inputUADict['source'] +  "\n" +     # Body
                      inputUADict['ip_address'] + "\n" +   # Body
                      inputUADict['header'])               # Body

    return email_body


def print_pager_duty(request, inputUADict):
    user_name = inputUADict['user'].username if inputUADict['user'] else "NullUser"

    print("> ADMIN PAGER DUTY <")
    print(str(datetime.now()))
    print(inputUADict['action_type'])
    print(user_name)
    print(inputUADict['source'])
    print(inputUADict['ip_address'])
    print(inputUADict['header'])


# Generic function for logging an action. Place after whatever you care to record and pass a plain text inputAction description of what's happened. Requires a request object.
def log_user_action(request, inputAction):
    if get_client_ip(request) == os.environ.get('HOME_IP'):             # Check if admin to save on extraneous logging
        return None

    useraction_dict = format_useraction_dict(request, None, inputAction, None)

    if useraction_dict['source'] == "/":                                             # It's the home page
        useraction_dict['product'] = Product.objects.get(name="Home Page")           # Use the holder Product object for the home page
    elif "Error" in inputAction: ### TODO ###
        useraction_dict['product'] = Product.objects.get(name__icontains="Error")
    elif Product.objects.filter(name__icontains=useraction_dict['source'].replace("/", "")).exists():                  # Remove the backslash
        useraction_dict['product'] = Product.objects.get(name__icontains=useraction_dict['source'].replace("/", ""))   # Look up the subsite slug and see if a Product instance contains it (case insensitive)

    useraction_dict['category'] = useraction_dict['product'].category

    try:
        UserAction.objects.create(**useraction_dict)
        iterate_call_count(useraction_dict['product'])

    except Exception as e:                                  # Formerly just InternalError
        print(f'Error detected in writing UserAction {e}')
        send_pager_duty('email', f'>Tier 1: {e}<', format_useraction_email(request, useraction_dict))


# Escalate certain actions to send the admin an email or text
def admin_pager_duty(request, user, inputAction):

    useraction_dict = format_useraction_dict(request, user, inputAction, "Receiver")
    useraction_dict['action_severity'] = 'Pager Duty'

    print_pager_duty(request, useraction_dict)

    # For requested invites and failed login
    if request and not user:
        UserAction.objects.create(**useraction_dict)
        useraction_dict['send_type'] = 'email'

    # Special escalation for admin to make sure strangers aren't prying into admin accounts
    elif user and user.is_superuser is True:
        useraction_dict['action_type'] = 'Admin: ' + useraction_dict['action_type']              # For formatting for logging and email sending

        if request and useraction_dict['ip_address'] is not os.environ.get('HOME_IP'):   # (e.g. logged-in callback signal,  Want to prevent escalating to an email send for our own actions, as it is duplicitous
            UserAction.objects.create(**useraction_dict)
            useraction_dict['send_type'] = 'text'

        elif not request:         # A pre-init or pre-save signal (e.g. changed-password and created-account callback signals do not include request.)
            UserAction.objects.create(**useraction_dict)
            useraction_dict['send_type'] = 'email'

    else:
        useraction_dict['action_type'] = 'Unknown: ' + useraction_dict['action_type']
        useraction_dict['send_type'] = 'email'


    if 'send_type' in useraction_dict.keys():
        send_pager_duty(useraction_dict['send_type'], useraction_dict['action_type'], format_useraction_email(request, useraction_dict))
        return True                                                    # Used in the if loops on the calling task side


def send_pager_duty(outputFormat, inputSubject, inputMessage):
    if outputFormat.title() == "Text":
        Later_Textly_API.Master_Textly(
            inputPhoneNumber=os.environ.get('ADMIN_PHONE'),
            inputMessage=f'{inputSubject} - {inputMessage}',
            inputSendTime=None)
    else:
        simple_email("--> Tier 0: " + inputSubject + " <--",             # Subject
                     inputMessage,
                     "admin@contextify.io")


############################# ~ Callback Signal Functions ~ ####################################

# Detect signal of a user logging in. sender is the sending db model
@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):

    print(f'-----> User Login: {user.username} via ip: {get_client_ip(request)} <-----')

    if user.is_superuser:
        admin_pager_duty(request, user, f'User log in: {user.username}')            # Escalate to pager duty if account is superadmin
    else:
        useraction_dict = format_useraction_dict(request, user, f'User log in: {user.username}', "Receiver")
        useraction_dict['action_severity'] = 'Informational'

        UserAction.objects.create(**useraction_dict)


# Detect signal of a user logging out
@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    print(f'-----> User Logout: {user.username} via ip: {get_client_ip(request)} <-----')

    useraction_dict = format_useraction_dict(request, user, f'User logged out: {user.username}', "Receiver")

    UserAction.objects.create(**useraction_dict)


# Detect a failed login attempt. Sometimes these are innocous, but multiple repeated attempts may be a brute force attack
@receiver(user_login_failed)
def user_login_failed_callback(sender, credentials, request, **kwargs):    # Note: we have credentials rather than user
    print(f'!!!! User Login Failed For: {credentials["username"]} via ip: {get_client_ip(request)} !!!!')

    try:
        user = User.objects.get(username=credentials['username'])              # Username and password (the hash of it) are provided in the credentials dict
    except (ObjectDoesNotExist, KeyError) as e:
        admin_pager_duty(request, None, f'Failed user log in {credentials}')
        return

    if user.is_superuser:
        admin_pager_duty(request, user, f'Failed user log in {user.username}')            # Escalate to pager duty if account is superadmin
    else:
        useraction_dict = format_useraction_dict(request, user, f'Failed user log in: {user.username}', "Receiver")
        useraction_dict['action_severity'] = 'Severe'

        UserAction.objects.create(**useraction_dict)

### TODO receiver?
def user_changed_password_callback(instance):
    try:
        user = User.objects.get(pk=instance.pk)
        old_password = user.password          # Remember: this is BEFORE saving the new password
    except ObjectDoesNotExist:
        user_signup_callback(instance)
        return

    if instance.password != old_password:
        useraction_dict = format_useraction_dict(None, user, f'User Changed Password: {user.username}', "Receiver")
        useraction_dict['action_severity'] = 'Informational'
        useraction_dict['source'] = "accounts/password_change/"
        UserAction.objects.create(**useraction_dict)

        if instance.is_admin == True:
            admin_pager_duty(None, user, f'User Changed Password: {user.username}')


def user_signup_callback(instance):             # Note we have instance rather than request. No auth here. Kwargs is empty. Instace = user
    # user = User.objects.filter(pk=instance.pk)
    useraction_dict = format_useraction_dict(None, None, f'New user signup: {instance.username}', "Receiver")
    useraction_dict['action_severity'] = 'Severe'
    useraction_dict['is_admin'] = instance.is_superuser
    UserAction.objects.create(**useraction_dict)

    if instance.is_superuser:
        send_pager_duty("text", "Tier 0: Superuser signup", f'{instance.username} - PK: {instance.pk}')

    simple_email("--> Tier 1: User Account Created  <--",             # Subject
                 str(datetime.now()) + "\n" +                         # Body
                 instance.username + "\n" +                           # Body
                 "Superuser status: " + str(instance.is_superuser),   # Body
                 "admin@contextify.io")                               # Recipient


##################################### ~ Cron Functions ~ ########################################


# @task() # Specify the frequency in settings.py
@periodic_task(
    run_every=(crontab(minute=59, hour=8)),
    name="859 daily periodic task",
    ignore_result=True)
def task_number_one():
    print('timebounded working')
    simple_email(f'--> Tier potato: {datetime.now()} <--',             # Subject
                     'timebounded daily working',
                     "admin@contextify.io")
    send_pager_duty("text", "hi", "its working")

@periodic_task(
    run_every=(crontab(minute=1, hour='*/12')),
    name="twice daily periodic task",
    ignore_result=True)
def task_number_two():
    print('task2working')
    simple_email(f'--> Tier 2 potato: {datetime.now()} <--',             # Subject
                     'twice daily periodic task',
                     "admin@contextify.io")

@periodic_task(run_every=timedelta(days=1), ignore_result=True)
def task_number_three():
    print('task3working')
    simple_email(f'--> Tier 3 potato: {datetime.now()} <--',             # Subject
                     'once daily periodic task',
                     "admin@contextify.io")


################################# ~ Outbound Requests ~ ####################################

# Mock a series of different browser / OS types
def rotate_agent():
    agents = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36',           # Desktop
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7',   # Desktop
              'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36',          # Desktop
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
              'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
              'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
              'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
              'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
              'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56',
              'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36',
              'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36', # # 1 Browser: Chrome 68.0 Win10 16-bit
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36', # # 2 Browser: Chrome 69.0 Win10 16-bit
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',] # # 3 Browser: Chrome 68.0 macOS 16-bit
    return random.choice(agents)   # Pick one at random

# Mock the refering domain. The mulitple occurance of certain search engines reflects their relative popularity
def rotate_referer():
    referers = ["www.bing.com",
                "www.yahoo.com",
                "www.google.com", "www.google.com", "www.google.com",
                "www.duckduckgo.com"]
    return random.choice(referers)

# @retryer
def site_request(inputURL, inputProxy, inputWaitTime, SoupOrResponse, optionalReferer, optionalPrint): # Mock a browser and visit a site
    if inputWaitTime != 0:
        sleep(random.uniform(inputWaitTime, inputWaitTime+1))    # +/- 0.5 sec from specified wait time. Pseudorandomized.

    headers = {                                                  # Spoof a typical browser header. HTTP Headers are case-insensitive.
        'accept-encoding': "gzip, deflate, br, sdch",
        'accept-language': "en-US,en;q=0.8",
        'upgrade-insecure-requests': "1",                        # Allow redirects from HTTP -> HTTPS
        'user-agent': rotate_agent(),
        'accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        'cache-control': "no-cache",
        'referer': optionalReferer or rotate_referer(),          # Note: this is intentionally a misspelling of referrer
        'cookie': "DUP=Q=p-1e7sgT2TeVOsixuurDTQ2&T=323541461&A=1&IG=F887695CE8DB413A9769E2AEA539A0B0; SRCHD=AF=NOFORM; SRCHUSR=DOB=20170217; MUIDB=136ED4AD626669CD3EB0DD7666666F34; ai_user=Zvjot|2017-04-26T17:16:46.235Z; MSFPC=ID=6cbbc0a91ebb7f40b5c62715ca15c89b&CS=3&LV=201706&V=1; SRCHUID=V=2&GUID=E28298B6F5654778AC666E3363107FAC&dmnchg=1; MUID=136ED4AD626669CD3EB0DD7666666F34; ASPSESSIONIDACARDCCC=DILPBHBDAJJCELLFPHLDNKBC; ASPSESSIONIDSSTABDCD=IGKGPGBDDKFPCMGLENBDEEEP; ASPSESSIONIDSQQBDBBD=HHEODJADIJIMADINKKJBBGFG; ASPSESSIONIDQSATCQBC=KHKMKOADEGGECODPNFNGJJJM; ASPSESSIONIDSSDBTCQD=BFEIKJADENOAMJFJLICBLFEM; ASPSESSIONIDSARARSQR=MKJIGHBDFCHHMDBDHAIEEDGK; ASPSESSIONIDCSCSAQSA=KILIBIBDJJMCEFILKNMPPGBO; ASPSESSIONIDASBSQCAQ=MPJEAGBDPCFGOJDBBJAOEFKA; ASPSESSIONIDSCBCRQAC=JNAHEDADNMOMOHMGAAKGKDGJ; _EDGE_S=mkt=en-us&SID=0FF2FE280B0C65A817E1F58C0A8B6406; _RwBf=s=70&o=18; BFBN=gRCsZvyg7Be07fmDsRpRlSzKhYCSCpc59Tx0QprO5aybDA; ASPSESSIONIDQATQRQBS=JNAHPDLBOLIBHNGOMKLFKJOO; ASPSESSIONIDSQQRRARR=DAABDLOBMEIADFKPHFFFJBLA; ASPSESSIONIDCCBDTSQS=PKGEAABCCGICKJALNDABPHKB; ASPSESSIONIDSSQQASBC=ACAOHDJAINGAIFDMOHMEHNOA; ASPSESSIONIDCSTRTQAQ=CJHBMELBBGCNLCJDBGCEPPBC; ASPSESSIONIDSATARBTR=CGICMEOBOHKDHKMNFPBEBOME; ASPSESSIONIDASCDTDBA=LONNBKFAPKBMAGNLPBAKFIDJ; ASPSESSIONIDSADQQRRT=DCAEPNCCKEGDBNJBDINAHBOB; ULC=T=8096|9:7&H=8096|6:6&P=8096|2:2; ipv6=hit=1522688253824&t=4; _SS=SID=0FF2FE280B0C65A817E1F58C0A8B6406&R=-1&bIm=357267&HV=1522687062&h5comp=0; SRCHHPGUSR=CW=748&CH=697&DPR=2&UTC=-240&WTS=63658281446&BLOC=T=170920|TS=154115",
        'DNT': "1",                                              # Ask the server to not be tracked (lol)
    }
    try:
        if inputProxy:
            proxies = {"http": inputProxy, "https": inputProxy}     # Format the proxies like requests requires
            response = requests.get(inputURL, headers=headers, proxies=proxies)
        else:
            response = requests.get(inputURL, headers=headers)

    except (MaxRetryError, ProxyError, SSLError, ProtocolError) as e:
        print(f'-----> ERROR. ROTATE YOUR PROXY. {e}<-----')
        return '-----> ERROR. ROTATE YOUR PROXY. <-----'
    except (Timeout, ConnectionError, HTTPError) as e:
        print(f'-----> ERROR. Request Threw: Effective 404. {e}<-----')
        return '-----> ERROR. Request Threw: Effective 404. <-----'
    except Exception as e:
        print(f'-----> ERROR. Request Threw: Unknown Error. {e}<-----')
        return '-----> ERROR. Request Threw: Unknown Error. <-----'

    if optionalPrint:
        display_site_data(response, inputURL, inputProxy, True)

    if response.status_code != 200:
        print(f'-----> ERROR. Request Threw: {response.status_code} <-----')
        if response.status_code in [502, 503, 999]:
            return f'-----> ERROR. Request Threw: {response.status_code}. ROTATE YOUR PROXY <-----'
        # elif response.status_code == 999:
            # return '-----> ERROR. Request Threw: 999. ROTATE YOUR PROXY <-----'

    if SoupOrResponse.lower() == "soup":                       # Allow functions to specify if they want parsed soup or plain request resopnse
        return BeautifulSoup(response.content, 'lxml')
    else:
        return response


def display_site_data(response, inputURL, inputProxy, optionalPrint): # Format (and optionally print) relevant site data

    if "-----> ERROR" in response:
        print('Cannot Display Error Response Site Data')
        return None

    site_data = {
        'Proxy': inputProxy,
        'Input_URL': inputURL,
        'Status_Code': response.status_code,
        'Content_Type': response.headers.get('content-type'),
        'Encoding': response.encoding,
        'Response_History': response.history,
        'Headers': response.headers,
        'Content': BeautifulSoup(response.content, 'lxml'),
        'Cookies': response.cookies,
    }
    if optionalPrint:
        pprint(site_data)

    return site_data


def get_all_links(inputURL):
    linklist = []
    parsed = site_request(inputURL, None, 1, 'soup', None, True) # Mock a browser and visit a site

    for links in parsed.find_all('a', href=True):
        link = links.get('href')
        linklist.append(link)
    print(len(linklist))
    return linklist


################################# ~ Proxies ~ ####################################


def fetch_proxies(): # Credit to https://www.scrapehero.com/how-to-rotate-proxies-and-ip-addresses-using-python-3/
    url = 'https://free-proxy-list.net/'  # Source of proxies
    proxy_lod = []                        # Note: a list of dicts
    response = requests.get(url)

    try:
        parsed = BeautifulSoup(response.content, 'lxml')
        if parsed:
            table = parsed.find('tbody')
            # print(table)
            rows = table.find_all('tr')
            for row in rows:
                proxy = {}
                contents = row.contents
                if contents[6].text == 'yes':          # Only want proxies that support HTTPS
                    proxy['ip'] = contents[0].text
                    proxy['port'] = contents[1].text
                    proxy['full'] = ":".join([contents[0].text, contents[1].text])
                    proxy['location'] = contents[3].text
                    proxy['type'] = contents[4].text   # Options are: elite proxy, anonymous, transparent
                    if proxy['type'] != 'transparent': # Not a proxy at that point lol
                        proxy_lod.append(proxy)
        print('Found: ' + str(len(proxy_lod)) + ' proxies')
        return proxy_lod

    except Exception as e: # Suppress exceptions
        print (e)
        send_pager_duty("text", "Proxy fetch is broken", f'{e}')


def check_proxy_availability(inputProxyList, inputLocation):
    HQ_Proxies = set()
    if isinstance(inputProxyList, list):
        for proxy in random.sample(inputProxyList, len(inputProxyList)):
            if inputLocation.title() in proxy['location'] and proxy['type'] != 'transparent':
                HQ_Proxies.add(proxy['full'])

        proxies = list(HQ_Proxies)
        if len(HQ_Proxies) == 0:
            return False
        else:
            return True


def rotate_proxies(inputProxyList, optionalLocation, returnLocation): # Take the proxy list from fetch_proxies and return a tested, working proxy
    HQ_Proxies = set()
    if optionalLocation and isinstance(inputProxyList, list):
        for proxy in random.sample(inputProxyList, len(inputProxyList)):
            if optionalLocation.title() in proxy['location'] and proxy['type'] != 'transparent':
                HQ_Proxies.add(proxy['full'])

        proxies = list(HQ_Proxies)
        if len(HQ_Proxies) == 0:
            proxies = [d['full'] for d in inputProxyList] # Extract full ips
            proxies = random.sample(proxies, len(inputProxyList))
            # raise Exception('NotARealLocationError: Please try again with a real location')
    else:
        if isinstance(inputProxyList, tuple):
            print('--> You fed it a tuple <--')
            return None

        elif isinstance(inputProxyList, set):
            proxies = random.sample(list(inputProxyList), len(inputProxyList))

        elif isinstance(inputProxyList, list):            # List of dicts
            proxies = [d['full'] for d in inputProxyList] # Extract full ips
            proxies = random.sample(proxies, len(inputProxyList))

    result = iterate_async_taskpool(proxies)

    if returnLocation:               # If the calling fxn wants a dict of the proxy and its location
        searched_result = next((item for item in inputProxyList if item["full"] == result)) # Generator
        return {'result':result.strip(), 'location': searched_result['location'].strip()}

    # print(result)
    return result


@shared_task(name="Proxy_Iterate", trail=True)
def iterate_async_taskpool(inputList):
    taskpool = pool.Pool(size=10)
    for single_task in (taskpool.imap_unordered(test_proxy, inputList, maxsize=1)): # try every proxy in the pool with the fxn test_proxy
        if single_task:
            print('First successful response is: ' + str(single_task))
            return single_task


@shared_task(name="Proxy_Test", trail=True)
def test_proxy(inputProxy):
    url = 'https://httpbin.org/ip'
    try:
        requests.get(url, timeout=1.5, proxies={"http": inputProxy, "https": inputProxy})
        print(str(inputProxy) + " worked.")
        return inputProxy

    except:                 # Most free proxies will often get connection errors.
        print("Skipping. Connnection error on " + str(inputProxy))
        return None


################################# ~ Sending Emails ~ ######################################


def format_input_recipients(inputRecipients): # EmailMessage must have a list in the to field
    if isinstance(inputRecipients, str):
        print('Sending email to ' + inputRecipients)
        return [inputRecipients]
    elif isinstance(inputRecipients, list):
        print('Sending email to ' + ', '.join([str(x) for x in inputRecipients]))
        return inputRecipients
    else:
        try:
            return [inputRecipients]
        except Exception as e:
            print ('Your inputrecipients is the wrong type. The exception is: ' + str(e))


@shared_task(name="Send_Simple_Email", ignore_result=True)
def simple_email(inputSubject, inputMessage, inputRecipients):
    clean_recipients = format_input_recipients(inputRecipients)
    subject = inputSubject
    message = inputMessage
    email_from = settings.EMAIL_HOST_USER
    recipient_list = clean_recipients           # Note: needs to be a list, even if only 1 recipient
    send_mail(subject, message, email_from, recipient_list)


@shared_task(name="Send_Attached_Email", ignore_result=True)
def attached_email(inputCSVName, inputRecipients):
    try:
        clean_recipients = format_input_recipients(inputRecipients) # Standardize recipient format
        print(inputCSVName)

        fr = open(inputCSVName, "r")               # Necessary to open and read inputCSVName
        attached_csv = fr.read()                   # Remember inputCSVName is the file NAME, not the file CONTENTS

        row_count = sum(1 for row in attached_csv)   # Get number of rows in csv. The fastest way to do so.
        print('content count is: ' + str(row_count)) # Print said number
        if row_count < 2:
            print('--> THE CSV DID NOT POPULATE <--')
        if ".csv" not in inputCSVName:             # Rewrite name with extension so the attachment will open properly
            inputCSVName = inputCSVName + ".csv"

        email = EmailMessage(
            to=clean_recipients,
            from_email=settings.EMAIL_HOST_USER,   # Default is admin@contextify.io
            subject='Here is your file',
            body='Thank you for working with AlecCorp, a division of Alec Industries (TM)',
        )
        email.attach(inputCSVName, attached_csv, 'text/csv') # Note: The MIME type ('text/csv') is covered by RFC 7111
        email.send()

        UserAction.objects.create(
            user=User.objects.get(email=inputRecipients),
            is_admin=User.objects.get(email=inputRecipients).is_superuser,
            action_type=f'Sent {inputCSVName}',
            action_severity='Logging',
            source='Tasks.py',
            product = Product.objects.get(name="Receiver"),                    # Delineates this as initiated by the Reciever function of Django Signals
            header='None',
            category= "Holding",                                              # An arbitrary holder value in Product. Similar to above, but more general. Inconsequential except for filtering these out in subsequent SQL fxns and programmatic displays
            ip_address="0.0.0.0",
            )

    except Exception as e:
        send_pager_duty("text", "CSV did not send", f'Attempted {inputCSVName} - {e}')
        print (e)


################################# ~ File I/O Handling ~ ####################################


def handle_views_file(request, render_settings, inputDesiredHeaders, noFallbackHeaders):
    file = request.FILES['myfile']
    log_user_action(request, "Used {get_product(request)['Product']} via file: {file.name}")

    imported_dict = pd_import_sheet(file, file.content_type, inputDesiredHeaders)

    considered_errors = ['Every Header Error', 'Multiple Error']
    if noFallbackHeaders: # TODO If the calling fxn needs a specific set of headers to be in the file
        considered_errors.append('Header Error')

    if not any(x in considered_errors for x in imported_dict.keys()):
        render_settings['FYI'] = "Cool. Your file will be sent to your email today"
        render_settings['header_row'] = imported_dict['all_headers']
        return imported_dict, render_settings

    elif 'Every Header Error' in imported_dict.keys():
        error_values = imported_dict['Every Header Error']
        render_settings['FYI'] = error_values

    else:
        error_values = get_dict_item_by_substring("Error", imported_dict)
        render_settings['FYI'] = error_values

    send_pager_duty("Email", "! {request.user.username} File IO Error !", error_values + "\n" + get_product(request)["Product"].name + "\n" + file.name + "\n" + file.content_type + "\n" + str(datetime.now()))
    return False, render_settings


def pd_import_sheet(inputFile, inputFileType, inputDesiredHeaders):
    df = convert_to_dataframe(inputFile, inputFileType)
    df.columns = [x.title().strip() for x in list(df.columns.values)] # Convert headers to titlecase
    headers_list = list(df.columns.values)                    # Write the headers to a list
    result_dol = df.T.to_dict('list')
    row_count = len(df.index)

    matched_headers_dict = match_headers(inputDesiredHeaders, headers_list)

    output_dict = {
        "output_dol": result_dol,
        "found_headers": matched_headers_dict,
        "dataframe": df,
        "all_headers": headers_list,
        "row_count": row_count,
    }

    if matched_headers_dict:
        for val in matched_headers_dict.values():
            if "Error: Multiple" in val:
                output_dict['Multiple Error'] = val
            elif "Error: Header" in val:
                output_dict['Header Error'] = val
        if all("Error" in x for x in matched_headers_dict.values()):
            output_dict['Every Header Error'] = f'Error: Headers Not Found. Please add the columns: {inputDesiredHeaders}'


    return output_dict


def get_column_data(inputImportedDict, inputChoice1, inputChoice2):
    df = inputImportedDict['dataframe']
    found_headers = inputImportedDict['found_headers']

    if found_headers[inputChoice1] in list(df.columns.values):
        return df[found_headers[inputChoice1]].tolist()
    elif inputChoice2 and found_headers[inputChoice2] in list(df.columns.values):
        return df[found_headers[inputChoice2]].tolist()
    else:
        return None


def match_headers(inputDesiredHeaders, inputFileHeaders):
    if not inputDesiredHeaders:
        return

    output_dict = {}
    Permutations = {
        'Company':  ["Comapny", "Company", "Companies", "Cos", "Co's", "Companys", "Compnays"],
        'Website':  ["Url", "Urls", "Site", "Sites", "Website", "Websites", "Link", "Links"],
        'Keyword':  ["Keyword", "Keywords", "Query", "Queries", "Word", "Words", "Term", "Terms", "Key", "Keys"],
        'Title':    ["Title", "Titles", "Role", "Roles", "Job", "Jobs", "Position", "Positions"],
        'Location': ["Location", "Locations", "Place", "Places", "Geo", "Geos", "Address", "Addresses"],
        'Name':     ["Name", "Names", 'Handle', "Handles", "Account", "Accoutns", "Accounts"],
    }

    for header in inputDesiredHeaders:
        Header = header.title()
        if Header in inputFileHeaders:
            output_dict[Header] = Header

        elif Header in Permutations.keys():
            matched_values = compare_list_overlap(inputFileHeaders, Permutations[Header])
            if matched_values and len(matched_values) == 1:
                output_dict[Header] = matched_values[0]
            elif matched_values and len(matched_values) > 1:
                output_dict[Header] = f'Error: Multiple Matching Columns. Please rename column(s): {matched_values[1:]}'
            else:
                output_dict[Header] = f'Error: Header Not Found. Please name a column: {Header}'

    print(f'matched header dict is {output_dict}')
    return output_dict

def save_uploaded_file(inputRequest):

    file = inputRequest.FILES['myfile']
    filename = inputRequest.FILES.get('filename', None)
    filetype = file.content_type

    current_user = User.objects.get(username=inputRequest.user.get_username())

    log_user_action(inputRequest, 'User Uploaded a File')

    return file, filename, filetype

def try_pandas_encoding(inputFunction, inputFile):


    try:
        return inputFunction(inputFile)

    except UnicodeDecodeError:
        print('fallback encoding for pandas')

        file_result = chardet.detect(inputFile.read())  # or readline if the file is large
        file_encoding = file_result['encoding']
        return inputFunction(inputFile, encoding=file_encoding) # "ISO-8859-1")


def convert_to_dataframe(inputFile, inputFileType):

    if inputFileType.lower() in ["csv", "text/csv"]:
        df = try_pandas_encoding(pd.read_csv, inputFile)
    elif inputFileType.lower() in ["xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]:
        df = try_pandas_encoding(pd.read_excel, inputFile)
    elif inputFileType.lower() in ["txt", "text/plain"]:
        df = pd.read_csv(inputFile, sep=" ", header=None)
    elif inputFileType.lower() in ["json", "application/json"]:
        df = try_pandas_encoding(pd.read_json, inputFile)
    elif inputFileType.lower() in ["lod", "lol"]:
        df = try_pandas_encoding(pd.DataFrame, inputFile)
    elif inputFileType.lower() is "dol":
        df = try_pandas_encoding(pd.DataFrame.from_dict, inputFile)
    else:
        send_pager_duty("text", "Wrong File Type", f'Attempted {inputFile} - {inputFileType}')

    return df


def export_db(outputFormat, inputModel, inputResource, inputFilter, inputFilterValue): # CAN also supports JSON and YAML
    queryset = inputModel.objects.filter(inputFilter=inputFilterValue) # probably todo on key for kwargs
    dataset = inputResource().export(queryset)
    filename = inputModel + inputFilter
    return format_output(outputFormat, dataset, filename, True)


def format_output(outputFormat, inputDataset, outputFileName, fileTypeNecessary):
    if fileTypeNecessary:
        inputDataset = inputDataset + "." + outputFormat

    if outputFormat == "csv":
        response = HttpResponse(inputDataset, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename='+ outputFileName +".csv"

    if outputFormat == "xlsx":
        response = HttpResponse(inputDataset, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename='+ outputFileName +".xlsx"

    if outputFormat == "yaml":
        response = HttpResponse(inputDataset, content_type='text/yaml')
        response['Content-Disposition'] = 'attachment; filename='+ outputFileName + ".yaml"

    if outputFormat == "json":
        response = HttpResponse(inputDataset, content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename='+ outputFileName +".json"

    if outputFormat == "txt":
        response = HttpResponse(inputDataset, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename='+ outputFileName +".txt"

    return response


################################# ~ File Conversion  ~ ####################################


def csv_to_dict(inputCSV, outputType): # sunsetted
    if outputType == "dict":
        result_dict = convert_to_dataframe(inputCSV, "csv").T.to_dict('list') # TODO
    elif outputType == "dol":
        result_dict = convert_to_dataframe(inputCSV, "csv").T.to_dict('list')

    result_dict = href_all_links(result_dict)
    result_dict = output_checkmarks(result_dict)
    return result_dict

def pandas_to_dol(csv_file, includeHeader, outputResultDict):
    if includeHeader:
        output = pd.read_csv(csv_file, squeeze=True, header=None, keep_default_na=False).to_dict() #, index_col=0,
    else:
        output = pd.read_csv(csv_file, squeeze=True, keep_default_na=False).to_dict()
    print(output)

    if outputResultDict:
        output_result_dict = {}
        for k, v in output.items():
            output_result_dict[k] = list(v.values())

        return output_result_dict
    return output


def lod_to_csv(inputLOD, inputName):
    df = pd.DataFrame(inputLOD)
    print(f'Row count for {inputName} is: {len(df.index)}')

    df.to_csv(inputName, index=False, sep=',')

    return inputName

def lod_to_dol(inputLOD, inputHeader): ## Use {' ':list(output_lod[0].keys())}
    df = pd.DataFrame(inputLOD)

    if inputHeader:
        if isinstance(inputHeader, list):
            df = pd.DataFrame(inputLOD, columns=inputHeader)
            return df.T.to_dict('list')

        frame_dol = df.T.to_dict('list')
        result_dol = {**inputHeader, **frame_dol}

    else:
        frame_dol = df.T.to_dict('list')
        header_dict = {' ': list(df.columns.values)}    # Alphabetical
        result_dol = {**header_dict, **frame_dol}       # Zip the lists

    return result_dol


def lol_to_dol(inputLoL):
    return {k: v for k, v in enumerate(inputLoL)}


##########################################################################################

"""
The name of the file is important. Celery goes through all the apps in INSTALLED_APPS
and registers the tasks in tasks.py files.
Notice how we decorated the send_verification_email function with @app.task.
This tells Celery this is a task that will be run in the task queue.
Notice how we expect as argument user_id rather than a User object.
This is because we might have trouble serializing complex objects when sending the tasks to Celery. It's best to keep them simple.
"""
