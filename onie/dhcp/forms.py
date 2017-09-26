from django import forms

class DhcpForm(forms.Form):
    switch_name = forms.CharField(label='Switch name', max_length=100)
    ip_addr = forms.CharField(label='IP address', max_length=100)
    mac_addr = forms.CharField(label='MAC address', max_length=100)
    default_url = forms.CharField(label='Default url', max_length=100)