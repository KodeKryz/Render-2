from django.urls import path
from .views import obtener_productos, login_view

urlpatterns = [
	path('', login_view, name='login'),
	path('contactos', obtener_productos, name='obtener_productos'),
]