# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from .forms import DhcpForm
from dhcp.models import Post

# Create your views here.
dhcp_config = "/tmp/dhcpd.conf"
hosts_config = "/tmp/hosts"


def dhcp_switch_add(request):
    """
    :param request: It checks whether the request is 'POST' or not
    :return: Render the dhcp form as the return value
    """
    global dhcp_config
    display = Post.objects.all()
    if request.method == "POST":
        #print request.POST.getlist('switch')
        form = DhcpForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['switch_name']
            ip_addr = form.cleaned_data['ip_addr']
            mac_addr = form.cleaned_data['mac_addr']
            default_url = form.cleaned_data['default_url']
            form.save()

            dhcp_file = open(dhcp_config, "a")
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
    global hosts_config
    if request.method == "POST":
        switch = request.POST.getlist('switch')
        section = request.POST.getlist('section_name')[0]
        #print section
        hosts_file = open(hosts_config, "a")
        hosts_file.write("[" + section + "]\n")
        #print switch
        for switch_name in switch:
            p = Post.objects.get(switch_name=switch_name)
            str_hosts = switch_name + " ansible_host=" + p.ip_addr
            str_hosts += ' ansible_user="{{ SSH_USER }}" ansible_ssh_pass="{{ SSH_PASS }}"\n'
            #print str_hosts
            hosts_file.write(str_hosts)
        hosts_file.write("\n")
        hosts_file.close()
        return redirect('dhcp_switch_add')