# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from .forms import DhcpForm
from dhcp.models import Post

# Create your views here.


def dhcp_switch_add(request):
    """
    :param request: It checks whether the request is 'POST' or not
    :return: Render the dhcp form as the return value
    """
    display = Post.objects.all()
    if request.method == "POST":
        print request.POST.getlist('switch')
        form = DhcpForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['switch_name']
            ip_addr = form.cleaned_data['ip_addr']
            mac_addr = form.cleaned_data['mac_addr']
            default_url = form.cleaned_data['default_url']
            form.save()

            dhcp_file = open("/tmp/dhcpd.conf", "a")
            str_onie = "\nhost " + name
            str_onie += "{\nhardware ethernet " + ip_addr
            str_onie += ";\nfixed-address " + mac_addr
            str_onie += ";\noption host-name \"" + name + "\""
            str_onie += ";\noption default-url = \"" + default_url + "\""
            str_onie += ";\n}\n"
            dhcp_file.write(str_onie)
            dhcp_file.close()

            return render(request, 'dhcp/dhcp_switch_add.html', {'form': form, 'display': display})

    else:
        form = DhcpForm()
        return render(request, 'dhcp/dhcp_switch_add.html', {'form': form, 'display': display})


def make_host_file(request):
    if request.method == "POST":
        switch = request.POST.getlist('switch')
        section = request.POST.getlist('section_name')[0]
        print section
        hosts_file = open("/tmp/hosts", "a")
        hosts_file.write("[" + section + "]\n")
        print switch
        for switch_name in switch:
            p = Post.objects.get(switch_name=switch_name)
            str_hosts = switch_name + " ansible_host=" + p.ip_addr + '\n'
            print str_hosts
            hosts_file.write(str_hosts)
        hosts_file.write("\n")
        hosts_file.close()
        return redirect('dhcp_switch_add')