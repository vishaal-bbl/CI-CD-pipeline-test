from django.contrib import admin
from .models import User, UserProfile

class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio', 'phone_number', 'created_at', 'updated_at')
    search_fields = ('user__email', 'user__username', 'bio')

# Register your models
admin.site.register(User, UserAdmin)
admin.site.register(UserProfile, UserProfileAdmin)