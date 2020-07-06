from django.contrib import admin
from import_export.admin import ImportExportModelAdmin, ImportMixin
from .models import Person, Company, Product, APIKey, UserAction, IPList, PreapprovedUser

# Create a GUI view in the Admin portal for each db Model

@admin.register(Person)
class PersonAdmin(ImportExportModelAdmin):
    pass

@admin.register(Company)
class CompanyAdmin(ImportExportModelAdmin):
    pass

@admin.register(Product)
class ProductAdmin(ImportExportModelAdmin):
    pass

@admin.register(APIKey)
class APIKeyAdmin(ImportExportModelAdmin):
    pass

@admin.register(UserAction)
class UserActionAdmin(ImportExportModelAdmin):
    pass

@admin.register(IPList)
class IPListAdmin(ImportExportModelAdmin):
    pass

@admin.register(PreapprovedUser)
class PreapprovedUserAdmin(ImportExportModelAdmin):
    pass
