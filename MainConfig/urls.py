from django.urls import path, include, re_path
from django.contrib import admin
from webapp.models import APIKey, Product
from django.core.cache import cache
from django.conf.urls import handler404, handler500
from django.contrib.auth import get_user, logout, login, authenticate
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView

from tastypie.api import Api
import webapp.views
from webapp.resources import ProductResource, UserResource

admin.autodiscover()

# Register the resources (in resources.py) for the Tastypie API module
v1_api = Api(api_name='v1')
v1_api.register(UserResource())
v1_api.register(ProductResource())

# urlpatterns are inherited in descending order; if there is a conflict b/w regex subsites, paths higher up in the code will be chosen

urlpatterns = [                                                           # Note: more permissive schemes (ie regex) should go at the bottom
    re_path(r'^api/', include(v1_api.urls)),                              # Tastypie schema. Supports subdomain assignment.
    path('accounts/', include('django.contrib.auth.urls')),               # Login and logout. Vanilla Django Module.
    path('admin/', admin.site.urls),                                      # Admin panel and associated subsites.

    path('contact', webapp.views.contact, name='contact'),                # Contact form, differs info by login status
    path('profile', webapp.views.user_profile, name='user_profile'),      # User profile page, allowing them to view their information and utilization
    path('stack', webapp.views.stack, name='stack'),                      # Current software stack
    path('about', webapp.views.about, name='about'),                      # About the author TOOD

    path('invite', webapp.views.invite, name='invite'),                   # Net new user invite page, which is just a dumb wrapper over admin-pager-duty
    path('signup', webapp.views.signup, name='signup'),                   # User signup page

    path('check_ip', webapp.views.check_ip, name='check_ip'),             # Simple widget to check server and client ip
    path('get_proxy', webapp.views.get_proxy, name='get_proxy'),          # Simple widget to generate a tested proxy
    path('products', webapp.views.products, name='products'),             # Listing of current products. Pulls from db.
    path('test_url', webapp.views.test_URL, name='test_URL'),             # Quickly lookup a subsite and check schema

    path('sitemapper', webapp.views.sitemapper, name='sitemapper'),       # Old CC.py. Pulls down all known urls with common crawl
    path('checkered', webapp.views.checkered, name='checkered'),

    path('honeypot', webapp.views.honeypot, name='honeypot'),             # Dumb subsite to catch bots
    path('ref_test', webapp.views.ref_test, name='ref_test'),             # For testing redirects
    path('broken', webapp.views.broken, name='broken'),                   # For testing 500 errors
    path('testing/', webapp.views.testing, name='testing'),               # Currently unused. for quick testing.
    path('EasterEgg7', webapp.views.easteregg7, name='EasterEgg7'),       # For CTF
    re_path(r'^robots\.txt$', TemplateView.as_view(template_name="robots.txt", content_type='text/plain')), # Robots.txt for compliant bots
    re_path(r'^$', webapp.views.home, name='home'),                       # This is the home page
    path('home', webapp.views.home, name='home'),                         # Simple redirect to the main LP
]


handler404 = 'webapp.views.handler404'
handler500 = 'webapp.views.handler500'
# TODO: Make handler400 (Bad Request) and handler403 (Permission Denied)

