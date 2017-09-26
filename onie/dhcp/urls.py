from django.conf.urls import url
from . import views


urlpatterns = [
url(r'^host/$', views.make_host_file, name='make_host_file'),
url(r'^$', views.dhcp_switch_add, name='dhcp_switch_add'),

]