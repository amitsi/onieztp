from django.conf.urls import url
from . import views


urlpatterns = [
url(r'^$', views.dhcp_switch_add, name='dhcp_switch_add'),
]