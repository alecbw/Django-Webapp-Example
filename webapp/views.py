# -*- coding: utf-8 -*-
# Note: this is all custom to my linter and does not affect output #
# pylint: disable=C0103
# pylint: disable=C0111
# pylint: disable=C0301
# pylint: disable=W0311
# pylint: disable=W0105


from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed, HttpResponseNotFound, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user, logout, login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms.fields import CheckboxInput
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist, MultipleObjectsReturned
from django.db.utils import IntegrityError

from .models import APIKey, Product, UserAction, PreapprovedUser
from .resources import PersonResource, ProductResource
from .tasks import get_client_ip, export_db, format_output, get_user_email, fetch_proxies, rotate_proxies, check_proxy_availability, log_user_action, simple_email, admin_pager_duty, get_product_h3, output_checkmarks, clean_url_string, init_var, get_href, test_foo, invert_keys_and_values, pandas_to_dol, lod_to_dol, href_all_links, send_pager_duty, pd_import_sheet, get_column_data, convert_to_dataframe, count_form_entries, get_dict_item_by_substring, handle_views_file, modify_keys, df_missing_values, task_number_one, save_uploaded_file
from .forms import GenericForm, SitemapperForm, ProxyForm, ExtendedTextForm, InviteForm, SignUpForm, UploadForm, CheckboxForm
from .extensions import Test_URL_API, CC_API, Check_Sites_API
from .celery import app

from tastypie.models import ApiKey
from tablib import Dataset
from time import sleep
from datetime import datetime
import pandas as pd
import rollbar
import os
import requests
import time
import re
import csv
import io
import timeit
import resource


# The main, ungated landing page. (also href = '/') #
def home(request):
    log_user_action(request, "Visited the home page")
    if not request.user.is_authenticated:
        return render(request, 'base.html', {
            'preform_value':"""
            Hey there 👋,

            You can request an account <a href=https://www.contextify.io/invite>here.</a>

            Existing users can sign in <a href=https://www.contextify.io/accounts/login/>here.</a>

            You can view the site's stack <a href=https://www.contextify.io/stack>here.</a>


            Questions? => <a href="mailto:hello@contextify.io?Subject=Contextify%20Feedback"target="_blank">hello@contextify.io</a>

            """})

    else:
        return render(request, 'base.html', {
            'auth_only_value': f"""
            Hey {request.user.username} 👋,

            Thank you for trying out the Contextify platform

            Your feedback is invaluable as I refine and expand these products

            Please send any and all thoughts to <a href="mailto:alec@contextify.io?Subject=Contextify%20Feedback"target="_blank">alec@contextify.io</a>


            Quick links:
            <a href=https://www.contextify.io/products>Products</a>
            <a href=https://www.contextify.io/stack>Stack</a>
            <a href=https://www.contextify.io/profile>User Profile</a>
            """})


# Contact info page; different values if user is auth'd or not #
def contact(request):
    log_user_action(request, "Visited Contact")

    if request.user.is_authenticated:
      contact_message = ('Hey friendo! You can reach me at <a href="mailto:alec@contextify.io?Subject=Contextify%20Feedback"target="_blank">alec@contextify.io</a>')
    else:
      contact_message = ('Hey stranger! You can reach me at <a href="mailto:hello@contextify.io?Subject=Contextify%20Feedback"target="_blank">hello@contextify.io</a>')

    return render(request, 'base.html', {
        'preform_value': contact_message
        })


# A simple primer on the site's stack #
def stack(request, output_dict=None, output_dict_2=None):
    log_user_action(request, "Visited Stack")

    output_dict = {
        'Python': 'Language',
        'Django': 'Framework',
        'Postgres': 'Database',
        'Redis': 'Caching',
        'Celery/Gevent': 'Queuing + Async',
        'Heroku': 'IaaS',
        'Github': 'Versioning + Deploy',
        'Pandas': 'File I/O + Analysis',
        'Tastypie': 'API provisioning',
        'Twilio': 'Messaging',
        'Rollbar': 'Error Reporting',
        'New Relic': 'Application Performance Management',
        'Native Django': 'Auth + Permissions',
    }
    output_dict_2 = {
        'Custom': 'IP / User Agent Rotation',
        'Custom  ': 'Logging + Pager Duty',
        'Custom   ': 'Rate limiting + Monitoring',
    }

    return render(request, 'vertical_table.html', {
        'product_name': "Stack",
        'table_dict' : output_dict,
        'table_dict_2' : output_dict_2,
        'FYI_2': "Custom Built",
        })


# Allow anonymous visitors to request an invite. Simple passthorough to admin_pager_duty #
def invite(request, result_dict=None, form=InviteForm()):
    render_settings = {                     # A dict of variables to be passed to the HTML
        'submit_url': '/invite',            # Where the form POSTs to
        'button_text': "Request",           # Text on the button
        'upload_enabled': False,            # If true, display file upload GUI widget
        'FYI': "Enter your email below",    # How to text for the user
        'product_name': "Contextify Invite" # Displays in plain text at the top
        }

    if request.method == 'POST':            # If this is a POST request, the user has done something.
        form = InviteForm(request.POST)     # Populate the form with the request data
        if form.is_valid():                 # Simple validation to prevent spoofying
            try:
                validate_email(form.cleaned_data['field1']) # Ensure it is actually an email
                render_settings['FYI'] = "Thank you!"       # Update the helper text
                admin_pager_duty(                           # Push to pager duty workflow, which will propmpt an email to be sent
                    request=request,                        # Pass the WSGI object, which contains the info the user's browser sent the server
                    user=None,                              # User is not yet auth'd
                    inputAction='Requested Invite ' +  form.cleaned_data['field1'])

            except ValidationError:                                 # User entered a garbage string
                render_settings['FYI'] = "Please enter your email"  # Nice non-descript helper text
                log_user_action(request, 'Requested Garbage Invite ' +  form.cleaned_data['field1'])

    elif request.method == 'GET':                               # If a GET, the user is first visiting the subsite and has yet to enter data.
        log_user_action(request, "Visited Request Invite Page") # Log the interaction in the UserAction db model

    # Form and result_dict change through the if loops, so add them to the render_settings dict right before returning the rendered site #
    render_settings['form'] = form                               # The GenericForm, empty first, then filled by the user and submitted by POST
    render_settings['table_dict'] = result_dict                  # A {dict} of results. The HTML will attempt to make a table if there is info in it. In this subsite, result_dict is always None
    return render(request, 'genericform.html', render_settings)  # This will return first via the else loop with empty 'responses' / result variable


# A way for users to sign up. This checks the user provided data with the PreApprovedUsers list.
# If it finds a matching entry, it will pop the PreApprovedUser row and create the user.
# Just a FYI/TODO this is not perfect
def signup(request, result_dict=None, form=SignUpForm()):
    render_settings = {
        'submit_url': '/signup',
        'button_text': "Request",
        'FYI': "Enter your email below",
        'product_name': "Contextify Signup"
        }

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form_email = form.cleaned_data.get('email').strip()
            log_user_action(request, f'Used User Signup Page: {form_email}') # Log the interaction in the UserAction db model

            try:
                approved_user = PreapprovedUser.objects.get(email__iexact=form_email)
                user = form.save()
                user.refresh_from_db()  # Load the profile instance created by the signal
                user.is_active = True
                user.is_superuser = False
                user.is_staff = False
                user.username = approved_user.username
                user.save()

                login(request, user)

                PreapprovedUser.objects.filter(email__iexact=form_email).delete()
                print('Successfully deleted PreapprovedUser')
                log_user_action(request, f'Successful User Signup: {form_email}')
                send_pager_duty("Text", "User Signup", f'{form_email} - {approved_user.username}')

                time.sleep(2)
                return HttpResponseRedirect('/')


            except (IntegrityError, MultipleObjectsReturned) as e:
                print (e)
                user = User.objects.filter(email__iexact=form_email).earliest('date_joined')
                admin_pager_duty(                           # Push to pager duty workflow, which will propmpt an email to be sent
                    request=request,                        # Pass the WSGI object, which contains the info the user's browser sent the server
                    user=user,                              # User is not yet auth'd
                    inputAction=f'Attempted signup on existing account: {form_email} - {user}')
                render_settings['FYI'] = "Please contact support"

            except ObjectDoesNotExist as e:
                print (e)
                admin_pager_duty(                           # Push to pager duty workflow, which will propmpt an email to be sent
                    request=request,                        # Pass the WSGI object, which contains the info the user's browser sent the server
                    user=None,                              # User is not yet auth'd
                    inputAction=f'Attempted User Signup on non-approved account: {form_email}')
                render_settings['FYI'] = "Please ensure your email has been preapproved"
            except Exception as e:
                send_pager_duty("Text", "! User Signup Error !", f'{form_email} - {e}')


    elif request.method == 'GET':
        log_user_action(request, f'Visited User Signup Page')

    render_settings['form'] = form
    render_settings['table_dict'] = result_dict
    return render(request, 'genericform.html', render_settings)


# The user profile page. Displays a user's own data. Data vehicle is output_dict, which is a dict.   #
# V Redirect when user is not logged in. No need to provide an arg for this, as the default for login is set in settings.py
@login_required()
def user_profile(request):
    log_user_action(request, "Visited Account Page")
    current_user = User.objects.get(username=request.user.get_username())

    Excluded_Products = Product.objects.filter(development_status='Hold') | Product.objects.filter(development_status__contains="Testing") | Product.objects.filter(development_status__contains="Local")
    Production_Library = Product.objects.exclude(id__in=[o.id for o in Excluded_Products]) # Get all non-excluded products
    Used_Products = UserAction.objects.select_related().filter(                            # Get all UserAction that list the user and exclude holder-products
        user=current_user,
        product__in=Production_Library)

    try:
        ApiKeyBool = ApiKey.objects.filter(user_id=current_user.id).first().key
    except AttributeError:
        ApiKeyBool = "None"

    output_dict = {
        'Username':       current_user.username,
        'Password':       get_href("contextify.io/accounts/password_change", "Click here to change"),
        'Email':          current_user.email,
        'Date Joined':    (current_user.date_joined).strftime("%m/%d/%Y"),
        'API Key':        ApiKeyBool
    }

    output_dict_2 = {}
    for val in Production_Library:                     # Iterate through non-testing non-holding Products
        output_dict_2[val.name] = 0                    # Add each product as a key, zero as the values

    for val in Used_Products:                          # Each time that product comes up in a UserAction the user was logged in
        output_dict_2[val.product.name] += 1           # Increment the counter by 1

    return render(request, 'vertical_table.html', {
        'product_name': current_user.username + " Profile",
        'table_dict' : output_dict,
        'table_dict_2' : output_dict_2, # This will create two separate tables
        'FYI_2': "Module Utilization",  # Second helper text (this time as a second title)
        })


# The product overview page; shows Prod and Local Prod. Data vehicle is output_lod, which is a list of dicts.  #
# Render settings is a dict of common settings options; settings that change will be added later
@login_required()
def products(request):
    render_settings = {
        'product_name': "Products",
        'headers' : ['Product', 'Status', 'Description', 'Single', 'Iterative'],
        }

    log_user_action(request, "Visited Products")

    Excluded_Products = Product.objects.filter(development_status__in=['Hold', 'Testing', 'Admin Only'])
    Production_Library = Product.objects.exclude(id__in=[o.id for o in Excluded_Products])

    if request.user.is_superuser:
        Production_Library = Production_Library | Product.objects.filter(development_status__contains="Admin Only") # Combine product listings

    Production_Library = Production_Library.order_by('development_status', 'subsite')

    output_lod = []
    for product in Production_Library:
        output_row = {
            'name': product.name,
            'development_status': product.development_status,
            'description': product.description,
            'individual': product.individual,
            'iterative': product.iterative,
        }

        if product.subsite and product.development_status != "Stable Local":       # Overwrite name k,v with pre-formmated link href if in Prod
            output_row['name'] = get_href(product.subsite, product.name)

        output_row = output_checkmarks(output_row) # Converts True/False to Check/X

        output_lod.append(output_row)              # Append each dict into a list_of_dicts


    render_settings['table_list'] = output_lod
    return render(request, 'horizontal_table.html', render_settings)


#################################### ~ Micro Products ~ #######################################


# Allow user to check own and server IP addresses. Data vehicle is output_lod, which is a list of dicts. #
@login_required()
def check_ip(request):
    render_settings = {
        'product_name': "Check IP",
        'headers' : ['Server', 'Yours'],
        }

    log_user_action(request, "Visited Check IP")

    client_ip = get_client_ip(request)
    response = requests.get('https://httpbin.org/ip')
    response_ip = response.json()['origin']

    output_lod = [{'ip':response_ip, 'other_ip':client_ip}]

    render_settings['table_list'] = output_lod
    return render(request, 'horizontal_table.html', render_settings)


# Allow user to generate a tested proxy w/ optional location. Data vehicle is result_dict, which is a dict. #
@login_required()
def get_proxy(request, result_dict=None, form=ProxyForm()):
    render_settings = {
        'product_name': get_product_h3(request),
        'submit_url': '/get_proxy',
        'button_text': "Get Proxy",
        'FYI': "Enter a location or leave blank for any",
        }

    if request.method == 'POST':
        form = ProxyForm(request.POST)
        if form.is_valid():
            log_user_action(request, f'Used Get Proxy: {form.cleaned_data["field1"]}')
            render_settings['FYI'] = "Now testing proxies for you"

            proxies = fetch_proxies()              # Go get a list of proxies
            if check_proxy_availability(proxies, form.cleaned_data['field1']):
                render_settings['FYI'] = "New tested proxy for you"
                result_dict = rotate_proxies(proxies, form.cleaned_data['field1'], True) # Get the dict of responses

            else:
                render_settings['FYI'] = "Could not find a working proxy for that location. Here's a random one"
                result_dict = rotate_proxies(proxies, False, False) # Get the dict of responses
                print(result_dict)


    elif request.method == 'GET':
        log_user_action(request, f'Visited Get Proxy')

    render_settings['form'] = form
    render_settings['table_dict'] = result_dict
    return render(request, 'genericform.html', render_settings)


# Allow user to test a website with a web request. Data vehicle is result_dict, which is a dict. #
@login_required()
def test_URL(request, result_dict=None, form=CheckboxForm()):
    render_settings = {
        'product_name': get_product_h3(request),                        # Get and display name and short description
        'submit_url': '/test_url',
        'button_text': "Test URL",
        }

    if request.method == 'POST':
        form = CheckboxForm(request.POST)
        if form.is_valid(): log_user_action(request, f'Used Test_URL via form: {form.cleaned_data["field1"]}')

        if form.is_valid() and form.cleaned_data.get("generic_checkbox"):
            result_dict = Test_URL_API.site_lookup(form.cleaned_data['field1'], True)
            render_settings['raw_html'] = result_dict

        elif form.is_valid():
            result_dict = Test_URL_API.site_lookup(form.cleaned_data['field1'], False)
            render_settings['table_dict'] = result_dict


    elif request.method == 'GET':
        log_user_action(request, f'Visited Test URL')

    render_settings['form'] = form
    return render(request, 'genericform.html', render_settings)


#################################### ~ Some Sample Products ~ #######################################


# Map all subdomains of a URL. The export option triggers a much larger file to be run. Data vehicle is result_dict, which is a dict. #
@login_required()
def sitemapper(request, result_dol=None, form=SitemapperForm()):
    render_settings = {
        'product_name': get_product_h3(request),
        'submit_url': '/sitemapper',
        'button_text': "Map Site",
        'FYI': "For longer results, use the export",
        'header_row': ['URL', 'Status', 'Timestamp', 'Length', 'Language']
        }

    if request.method == 'POST':
        form = SitemapperForm(request.POST)

        if form.is_valid() and form.cleaned_data.get("generic_checkbox"):
            log_user_action(request, f'Used Sitemapper Export via form: {form.cleaned_data["field1"]}')

            CC_API.SM_Master_Iterate.delay(form.cleaned_data['field1'], get_user_email(request.user.username))
            render_settings['FYI'] = "Your file will be sent to your email"

        elif form.is_valid():
            log_user_action(request, f'Used Sitemapper Print via form: {form.cleaned_data["field1"]}')

            result_dol = CC_API.SM_Master_Iterate(form.cleaned_data['field1'], None)
            render_settings['FYI'] = "Your results are below"


    elif request.method == 'GET':
        log_user_action(request, f'Visited Sitemapper')

    render_settings['form'] = form
    render_settings['table_dol'] = result_dol
    return render(request, 'genericform.html', render_settings)


@login_required()
def checkered(request, result_dol=None, form=UploadForm()):
    render_settings = {
        'submit_url': '/checkered',
        'button_text': "Submit",
        'product_name': get_product_h3(request),
        'upload_enabled': True,
        'FYI': "Upload file below",
        }

    if request.method == 'POST':
        form = UploadForm(request.POST)

        if request.FILES:
            imported_dict, render_settings = handle_views_file(request, render_settings, ["Website"], False)
            if imported_dict:
                website_list = get_column_data(imported_dict,"Website", None)

                result_dol = imported_dict['output_dol']
                Check_Sites_API.CK_Master_Iterate.delay(website_list, get_user_email(request.user.username))

                render_settings['FYI'] = 'Cool. Your file will be sent to your email today'


    elif request.method == 'GET':
        log_user_action(request, "Visited Checkered")

    render_settings['form'] = form
    render_settings['table_dol'] = result_dol
    return render(request, 'genericform.html', render_settings)




#################################### ~ Errors and Misc ~ #######################################

# A way to record which bots are following all hrefs. TODO: auto-blacklist honeypot IPs
def honeypot(request):
    log_user_action(request, "Visited Honeypot")
    return render(request, 'base.html', {'preform_value' :'mmm tasty honey'})


# Display a page and suppress the stack trace for 404 errors
def handler404(request, exception, template_name='404.html'):
    subsite = request.META.get('PATH_INFO')

    print(f'--> handled 404: {subsite} <--')
    print(request.META)

    log_user_action(request, f'404 Error: {subsite}')

    return render(request, '404.html', status=404)


# Display a page and suppress the stack trace for 500 errors
def handler500(request, template_name='500.html'):
    subsite = request.META.get('PATH_INFO')

    user_email = get_user_email(request)
    if not user_email:
        user_email = "No Email; user not auth'd"

    print(f'--> handled 500: {subsite}<--')
    print(request.META)

    log_user_action(request, f'500 Error: {subsite}')

    if request.user and not request.user.is_superuser:
        send_pager_duty("Text", f'500 error: {subsite}', f'{request.user.username} - {request.META.get("HTTP_USER_AGENT")}')

    simple_email(f'--> Tier 1: 500 Error: {subsite} <--',             # Subject
                 str(datetime.now()) + "\n" +
                 str(request.META.get('HTTP_USER_AGENT')) + "\n" +
                 str(get_client_ip(request)) + "\n" +                     # Body
                 request.user.username + "\n" +
                 user_email,
                 "admin@contextify.io")

    return render(request, '500.html', status=500)


@login_required()
def testing(request):
    # task_number_one()
    log_user_action(request, "Visited testing")
    return HttpResponse(request.META)

def ref_test(request):
    return HttpResponseRedirect('/testing')


# This subsite is intentionally broken for testing
@login_required()
def broken(request):
    log_user_action(request, "Visited Broken")
    if request.user.is_superuser:
        print (broken)
        test_foo.delay()
    print(request.META)
    return HttpResponse(request.META)

# so you can look at the Celery queue
@login_required
def queue(request):
    log_user_action(request, "Visited Queue Subsite")
    from celery.task.control import inspect

    # Inspect all nodes.
    i = inspect()

    # Show the items that have an ETA or are scheduled for later processing
    # Show tasks that are currently active.
    # Show tasks that have been claimed by workers
    output_dict = {
        'scheduled': i.scheduled(),
        'active': i.active(),
        'reserved': i.reserved(),
        'active_queue': app.control.inspect().active_queues(),
        'all_nodes': app.control.inspect()
    }

    return render(request, 'vertical_table.html', {
        'product_name': 'Queue',
        'table_dict' : output_dict,
        'FYI_2': "Current Queue",  # Second helper text (this time as a second title)
    })
