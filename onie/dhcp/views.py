# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render  # , redirect
from .forms import DhcpForm

# Create your views here.


def dhcp_switch_add(request):
    """
    :param request: It checks whether the request is 'POST' or not
    :return: Render the dhcp form as the return value
    """
    if request.method == "POST":
        form = DhcpForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['switch_name']
            ip_addr = form.cleaned_data['ip_addr']
            mac_addr = form.cleaned_data['mac_addr']
            default_url = form.cleaned_data['default_url']

            dhcp_file = open("/etc/dhcp/dhcpd.conf", "a")
            str_onie = "\nhost " + name
            str_onie += "{\nhardware ethernet " + ip_addr
            str_onie += ";\nfixed-address " + mac_addr
            str_onie += ";\noption host-name \"" + name + "\""
            str_onie += ";\noption default-url = \"" + default_url + "\""
            str_onie += ";\n}\n"
            dhcp_file.write(str_onie)
            dhcp_file.close()
            return render(request, 'dhcp/dhcp_switch_add.html', {'form': form})

    else:
        form = DhcpForm()
        return render(request, 'dhcp/dhcp_switch_add.html', {'form': form})
