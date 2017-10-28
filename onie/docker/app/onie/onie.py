import click
from cryptography.fernet import Fernet
import csv
import datetime
import glob
from isc_dhcp_leases import Lease, IscDhcpLeases
from netaddr import IPNetwork
import os
import re
import requests
import socket
import struct
import subprocess
from sqlalchemy import exc
import sqlite3
import time

from flask import Flask, Response, request, session, g, redirect, url_for, abort, \
     render_template, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

DEBUG = os.environ.get('FLASK_DEBUG', False)
if DEBUG == 'false':
    DEBUG = False

application = Flask(__name__) # create the application instance :)
application.config.from_object(__name__) # load config from this file , onie.py

requests.packages.urllib3.disable_warnings() # FIXME

# Load default config and override config from an environment variable
application.config.update(dict(
    SQLALCHEMY_DATABASE_URI='sqlite:////ztpvol/onie.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=True,
    SECRET_KEY='secret',
    USERNAME='admin',
    PASSWORD='test123',
    TRAP_BAD_REQUEST_ERRORS=True,
))
application.config.from_envvar('ONIE_SETTINGS', silent=True)
db = SQLAlchemy(application)
migrate = Migrate(application, db)

#
# UTILS
#

PNC_RELOGIN_INTERVAL = 300 # seconds
PNC_LOGIN = 'https://cloud-web.pluribusnetworks.com/api/login'
PNC_ORDER_DETAILS = 'https://cloud-web.pluribusnetworks.com/api/orderDetails'
PNC_ORDER_ACTIVATION = 'https://cloud-web.pluribusnetworks.com/api/orderActivations'
PNC_ACTIVATION_KEY_FOR = 'https://cloud-web.pluribusnetworks.com/api/offline_bundle/{0}'.format
PNC_ONIE_DOWNLOAD_FOR = 'https://cloud-web.pluribusnetworks.com/api/download_image1/{0}?version={1}'.format
PNC_ASSETS = 'https://cloud-web.pluribusnetworks.com/api/assets'
PNC_PRODUCTS = 'https://cloud-web.pluribusnetworks.com/api/products'
ONIE_INSTALLER_RE = re.compile(r'^onie-installer-([\d\.]+)-(\d+)$')
NGINX_ACCESS_LOG_RE = re.compile(r'(?P<ip>[\d\.]+) - - \[(?P<datetime>[^\]]+)\] "(?P<verb>\w+) (?P<url>/images/..*?) HTTP/[\d\.]+" (?P<statuscode>\d+) (?P<bytes>\d+)')

KEYFILE = '/ztpvol/.key'
LEASES_FILE = '/var/lib/dhcp/dhcpd.leases'
NGINX_ACCESS_LOG = '/var/log/nginx/access.log'
TSHARK_LOG = '/var/log/tshark.log'
DHCP_INTERFACE_NAME = '/var/run/dhcp_interface'
TECH_SUPPORT_ARCHIVER = '/tech-support-archive.sh'
TECH_SUPPORT_ARCHIVE_DIR = '/ztpvol/html/images/tech-support-bundles'
TECH_SUPPORT_ARCHIVE_RE = re.compile(r'^ARCHIVE=(.*)')

WWW_ROOT = '/var/www/html/images'
ONIE_INSTALLER_PATH = os.path.join(WWW_ROOT, 'onie-installer')
LICENCE_PATH_10G = os.path.join(WWW_ROOT, 'license_10g/onvl-activation-keys')
LICENCE_PATH_40G = os.path.join(WWW_ROOT, 'license_40g/onvl-activation-keys')
ANSIBLE_HOSTS_LIST = os.path.join(WWW_ROOT, 'ansible_hosts')

DEVICE_TYPE_10G = '10g'
DEVICE_TYPE_40G = '40g'

IP_ADDR_RE = re.compile(r'^\s*inet ([\d\.]+/\d{1,2})')

DHCPD_CONFIG = '/etc/dhcp/dhcpd.conf'
ACTIVATION_KEY_FILES = {
    DEVICE_TYPE_10G: os.path.join(WWW_ROOT, 'license_10g/onvl-activation-keys'),
    DEVICE_TYPE_40G: os.path.join(WWW_ROOT, 'license_40g/onvl-activation-keys'),
}

SERVICE_NAME_MAP = {
    'dhcpd': 'DHCP',
    'nginx': 'HTTP',
    'tshark': 'TShark',
}

EX_CSV_IMPORT_DUP_RE = re.compile(r"UNIQUE constraint failed.*\[parameters: \('([^']+)'")

SUPERVISOR = 'supervisorctl'
DHCPD_PROC = 'dhcpd'
TSHARK_PROC = 'tshark'
REPORT_SERVICES = ( DHCPD_PROC, )

class PnCloud:
    __instance = None

    def __init__(self):
        self.session = requests.Session()
        self.logged_in = False
        self.login_time = 0
        self.session.verify = False  # FIXME
        self.username = None
        self.full_name = None

    @classmethod
    def get(klass):
        if not klass.__instance:
            klass.__instance = klass()
        return klass.__instance

    def get_pnc_account_details(self):
        pnca = PnCloudAccount.query.all()
        if pnca:
            return pnca[0]
        else:
            return None

    def _api_request(self, session, url, data=None):
        kwargs = {}
        if data:
            kwargs['data'] = data
            if DEBUG:
                ddata = data.copy()
                for k in ddata:
                    if re.search(r'password', k, re.IGNORECASE):
                        ddata[k] = "XXXXXXXX"
                print("DEBUG: data={0}".format(ddata))
        r = session(url, **kwargs)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            print("Request failed: {0}: {1} {2}".format(url, r.status_code, r.text))
            return {}

    def _api_post(self, url, data={}):
        if 'csrfmiddlewaretoken' not in data and 'csrftoken' in self.session.cookies:
            print("Adding CSRF token to request: {0}".format(url))
            data['csrfmiddlewaretoken'] = self.session.cookies['csrftoken']
        return self._api_request(self.session.post, url, data)

    def _api_get(self, url):
        return self._api_request(self.session.get, url)

    def login(self):
        if self.logged_in and time.time() - self.login_time > PNC_RELOGIN_INTERVAL:
            print("Re-logging in to PN cloud")
            self.logged_in = False

        if not self.logged_in:
            print("Logging in to PN cloud")
            pnca = self.get_pnc_account_details()
            if not pnca:
                print("PN cloud details not configured")
                return False

            data = {"login_email": pnca.username, "login_password": decrypt_password(pnca.password)}
            resp = self._api_post(PNC_LOGIN, data)
            self.logged_in = resp.get('success', False)
            if self.logged_in:
                self.login_time = time.time()
                self.username = resp.get('username', '')
                self.full_name = resp.get('full_name', '')

        if self.logged_in:
            print("Logged in as user: {0} ({1})".format(self.username,
                self.full_name))
        else:
            print("Failed to log in as user: {0}".format(pnca.username))

        return self.logged_in

    def logout(self):
        if self.logged_in:
            print("Logging out user: {0} ({1})".format(self.username,
                self.full_name))
            self.logged_in = False
        return True

    def order_details(self):
        if not self.logged_in:
            print("Not logged in")
            return False

        order_det = self._api_get(PNC_ORDER_DETAILS)
        return order_det.get('order_details', [])

    def assets(self):
        if not self.logged_in:
            print("Not logged in")
            return False

        assets = self._api_get(PNC_ASSETS)
        return assets.get('assets', [])

    def products(self, download_group_ids=(), sw_pid_pattern=None):
        if not self.logged_in:
            print("Not logged in")
            return False

        products = self._api_get(PNC_PRODUCTS).get('products', [])
        if download_group_ids:
            products = [x for x in products if x['download_group_id'] in download_group_ids]
        if sw_pid_pattern:
            products = [x for x in products if sw_pid_pattern.search(x['sw_pid'])]

        for product in products:
            product['__downloaded'] = os.path.isfile(os.path.join(WWW_ROOT, product['sw_pid']))

        return products

    def activation_key_download(self, dtype):
        if not self.logged_in:
            raise Exception("Not logged in")

        det = self.order_details()
        order_details = {
            DEVICE_TYPE_10G: det[0],
            DEVICE_TYPE_40G: det[1],
        }
        self.activation_key(order_details[dtype]['id'],
                ACTIVATION_KEY_FILES[dtype])

    def activation_key(self, order_id, filename):
        print("Fetching activation key for order \"{0}\" into {1}".format(
            order_id, filename))
        r = self.session.get(PNC_ACTIVATION_KEY_FOR(order_id), stream=True)
        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def activate(self, device):
        if not self.logged_in:
            raise Exception("Not logged in")

        result = self._api_post(PNC_ORDER_ACTIVATION, device)
        return result

    def activate_device_id(self, device_id, device_type):
        if not self.logged_in:
            print("Not logged in")
            return False

        det = self.order_details()
        order_details = {
            DEVICE_TYPE_10G: det[0],
            DEVICE_TYPE_40G: det[1],
        }
        details = order_details[device_type]
        active = [x for x in details['order_activations'] if x['device_id'] == device_id]
        if active:
            print("Device already active: {0}; activation date: {1}".format(
                device_id, active[0]['activation_date']))
            return True

        print("Activating device: {0}".format(device_id))
        order_id = order_details[device_type]['id']
        device = {"order_detail_id": order_id,
                "device_ids": device_id}
        return self.activate(device)

    def onie_download(self, installer, installer_vers):
        if not self.logged_in:
            raise Exception("Not logged in")

        url = PNC_ONIE_DOWNLOAD_FOR(installer, installer_vers)
        print("Downloading: {0}".format(url))

        outfile = os.path.join(WWW_ROOT, installer)

        r = self.session.get(url, stream=True)
        with open(outfile, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        
        if r.status_code != requests.codes.ok:
            print("Failed to download ONIE installer: {0}: {1}".format(
                url, r.status_code))
            if os.path.isfile(outfile):
                print("Removing file: {0}".format(outfile))
                os.remove(outfile)
            return ''

        return outfile

def encrypt_password(password):
    if not os.path.isfile(KEYFILE):
        with open(KEYFILE, 'wb') as f:
            f.write(Fernet.generate_key())

    with open(KEYFILE, 'rb') as f:
        key = f.read()

    f = Fernet(key)
    if not isinstance(password, bytes):
        password = password.encode()
    return f.encrypt(password)

def decrypt_password(password):
    with open(KEYFILE, 'rb') as f:
        key = f.read()

    f = Fernet(key)
    return f.decrypt(password).decode('utf-8')

#
# FLASK
#

@application.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    db.create_all()
    print('Initialized the database.')

#
# MODELS
#

class DhcpClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(80), unique=True, nullable=True)
    ip = db.Column(db.String(40), unique=True, nullable=False)
    mac = db.Column(db.String(18), unique=True, nullable=False)
    tag = db.Column(db.String(20), nullable=True)
    device_id = db.Column(db.String(40), unique=True, nullable=True)
    device_type = db.Column(db.String(20), nullable=False)
    default_url = db.Column(db.String(256), nullable=True)

    server_id = db.Column(db.Integer, db.ForeignKey('dhcp_subnet.id'))

    def __repr__(self):
        return "<DhcpClient {0}>".format(self.hostname)

class DhcpSubnet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subnet = db.Column(db.String(40), nullable=False)
    subnet_mask = db.Column(db.String(40), nullable=False)
    dhcp_range_start = db.Column(db.String(40), nullable=True)
    dhcp_range_end = db.Column(db.String(40), nullable=True)
    dns_primary = db.Column(db.String(40), nullable=True)
    dns_secondary = db.Column(db.String(40), nullable=True)
    domain_name = db.Column(db.String(128), nullable=True)
    gateway = db.Column(db.String(40), nullable=True)
    broadcast_address = db.Column(db.String(40), nullable=True)
    dhcp_interface = db.Column(db.String(40), nullable=True)
    default_url = db.Column(db.String(256), nullable=True)

    clients = db.relationship("DhcpClient")

    @classmethod
    def get(klass):
        inst = klass.query.all()
        if inst:
            return inst[0]
        else:
            # Compute defaults
            print("Computing defaults for DHCP subnet")
            params = get_subnet_details()
            record_interface(params['dhcp_interface'])
            entry = klass(**params)
            db.session.add(entry)
            db.session.commit()

            if request and write_dhcpd_conf():
                launch()

            return entry

        return None

    @classmethod
    def ip_for_interface(klass, intf):
        p = subprocess.Popen(['ip', 'addr', 'show', intf],
                stdout=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        myip = None
        for line in stdout.splitlines():
            m = IP_ADDR_RE.search(line.decode('ascii'))
            if m:
                myip = m.group(1)
                break
        if myip:
            return IPNetwork(myip)
        return None

    @property
    def server_ip(self):
        if self.dhcp_interface:
            intf = self.dhcp_interface
        else:
            intf = os.environ.get('DHCP_INTERFACE', 'eth0')

        myip = DhcpSubnet.ip_for_interface(intf)
        if not myip:
            print("Failed to obtain IP for interface: {0}".format(intf))
            return None

        return myip

    @property
    def server_port(self):
        return int(os.environ.get('HTTP_PORT', '5000'))

    @property
    def relayed_subnet(self):
        if not self.server_ip or not self.subnet or not self.subnet_mask:
            return False
        try:
            subnet = IPNetwork("{0}/{1}".format(self.subnet, self.subnet_mask))
            if self.server_ip.ip not in subnet:
                return True
        except Exception as e:
            print("Attempt to detect DHCP relay failed: {0}".format(e))

        return False

    @property
    def onie_url(self):
        if self.default_url:
            return self.default_url
        return "http://{0}:{1}/images/onie-installer".format(self.server_ip.ip, self.server_port)

class PnCloudAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    onie_version = db.Column(db.String(40), nullable=True)
    username = db.Column(db.String(40), nullable=True)
    password = db.Column(db.String(40), nullable=True)

    @classmethod
    def get(klass):
        inst = klass.query.all()
        if inst:
            return inst[0]
        return None

class AnsibleConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ssh_user = db.Column(db.String(40), nullable=True)
    ssh_pass = db.Column(db.String(40), nullable=True)

    @classmethod
    def get(klass):
        inst = klass.query.all()
        if inst:
            return inst[0]
        return None

    @property
    def ssh_pass_decrypted(self):
        return decrypt_password(self.ssh_pass)

class AnsibleHostsFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=True)
    filename = db.Column(db.String(25))
    hosts = db.Column(db.Text())

#
# VIEWS
#

def onie_installer_details(installer):
    m = ONIE_INSTALLER_RE.search(installer)
    ret = { 'installer': installer }
    if not m:
        ret['name'] = installer.replace('onie-installer-', '')
        ret['version'] = 'Unknown'
        return ret

    major = m.group(1)
    minor = m.group(2)
    majorcode = ''.join([ ("%02d" % int(x)) for x in major.split('.') ]).lstrip('0')
    if minor.startswith(majorcode):
        minor = minor[len(majorcode):]

    ret['version'] = "{0}-{1}".format(major, minor)
    ret['name'] = "ONVL {0} ONIE".format(ret['version'])
    return ret

@application.route('/')
def show_entries():
    server = DhcpSubnet.get()
    clients = DhcpClient.query.order_by(DhcpClient.hostname).all()
    pnca = PnCloudAccount.get()
    ansible = AnsibleConfig.get()
    hostfiles = AnsibleHostsFile.query.order_by(AnsibleHostsFile.filename.desc()).all()
    servstats = service_status(('dhcpd', 'tshark'))
    assets = []
    products = []
    activation_keys = {}
    activations_by_device_id = {}
    if server.server_ip:
        http_base = "http://{0}:{1}".format(server.server_ip.ip, server.server_port)
    else:
        http_base = ''

    onie_installers = [os.path.basename(x) for x in glob.glob(os.path.join(WWW_ROOT, 'onie-installer-*'))]
    if os.path.islink(ONIE_INSTALLER_PATH):
        current = os.path.basename(os.readlink(ONIE_INSTALLER_PATH))
    else:
        current = ''

    pnc = PnCloud.get()
    if pnc.login():
        assets = pnc.assets()
        products = pnc.products(download_group_ids=(1,), sw_pid_pattern=re.compile(r'^onie-installer-'))
        for dtype in ACTIVATION_KEY_FILES:
            if os.path.isfile(ACTIVATION_KEY_FILES[dtype]):
                activation_keys[dtype] = re.sub(r'^.*/images/', '/images/', ACTIVATION_KEY_FILES[dtype])
            else:
                activation_keys[dtype] = None

        for det in pnc.order_details():
            for a in det['order_activations']:
                activations_by_device_id[a['device_id']] = True
    elif pnca and pnca.username and pnca.password:
        flash("Failed to log in to PN Cloud as user \"{0}\"".format(pnca.username))

    downloaded = [ x['sw_pid'] for x in products if x['__downloaded'] ]
    uploaded = [ onie_installer_details(x) for x in onie_installers if x not in downloaded ]

    dhcp_leases = []
    if os.path.isfile(LEASES_FILE):
        dhcp_leases = reversed(IscDhcpLeases(LEASES_FILE).get())

    services = [ x for x in servstats if x['service_id'] in REPORT_SERVICES ]
    ts = [ x['status'] for x in servstats if x['service_id'] == 'tshark' ]
    if ts:
        tshark_status = ts[0]
    else:
        tshark_status = 'UNKNOWN'

    return render_template('show_entries.html', server=server,
            entries=clients, pnca=pnca, ansible=ansible, hostfiles=hostfiles,
            assets=assets, products=products, activation_keys=activation_keys,
            activations_by_device_id=activations_by_device_id, onie_installers=onie_installers,
            uploaded=uploaded, current=current, services=services, http_base=http_base,
            dhcp_leases=dhcp_leases, tshark_status=tshark_status)

def get_default_interface():
    with open('/proc/net/route') as f:
        for line in f.readlines()[1:]:
            (intf, dest, gateway, x) = line.split(None, 3)
            if dest == '00000000':
                gateway = socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
                return (intf, gateway)
    return (None, None)

def get_gateway_for_interface(interface):
    with open('/proc/net/route') as f:
        for line in f.readlines()[1:]:
            (intf, dest, gateway, x) = line.split(None, 3)
            if intf == interface:
                return socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
    print("Failed to identify gateway for interface {0}".format(interface))
    return ''

def get_subnet_details(interface=None):
    if not interface:
        (interface, gateway) = get_default_interface()
        if not interface:
            print("Failed to determine default interface")
            return {}
    else:
        gateway = get_gateway_for_interface(interface)

    ipnet = DhcpSubnet.ip_for_interface(interface)
    if not ipnet:
        print("Failed to load network details for interface: {0}".format(interface))
        return {}

    ip = str(ipnet.ip)
    subnet = str(ipnet.network)
    subnet_mask = str(ipnet.netmask)
    broadcast_address = str(ipnet.broadcast)

    dns_primary = ''
    dns_secondary = ''
    domain_name = ''
    with open('/etc/resolv.conf') as f:
        for line in f.readlines():
            if line.startswith('nameserver'):
                dns = line.split()[1]
                if not dns_primary:
                    dns_primary = dns
                elif not dns_secondary:
                    dns_secondary = dns
            elif line.startswith('search'):
                domain_name = line.split()[1]

    return {
        'dhcp_interface': interface,
        'subnet': subnet,
        'subnet_mask': subnet_mask,
        'broadcast_address': broadcast_address,
        'dhcp_range_start': ip,
        'dhcp_range_end': ip,
        'dns_primary': dns_primary,
        'dns_secondary': dns_secondary,
        'domain_name': domain_name,
        'gateway': gateway,
        'default_url': "http://{0}:{1}/images/onie-installer".format(
                            ipnet.ip, int(os.environ.get('HTTP_PORT', '5000'))),
    }

def record_interface(interface):
    print("Recording the DHCP interface: {0}".format(interface))
    with open(DHCP_INTERFACE_NAME, 'w') as f:
        f.write(interface + "\n")

@application.route('/confsubnet', methods=['POST'])
def configure_subnet():
    entry = DhcpSubnet.get()
    old_dhcp_interface = None
    if entry:
        old_dhcp_interface = entry.dhcp_interface
    params = {}
    for p in [ 'subnet', 'subnet_mask', 'dhcp_range_start',
               'dhcp_range_end', 'dns_primary', 'dns_secondary',
               'domain_name', 'gateway', 'broadcast_address',
               'dhcp_interface', 'default_url' ]:
        params[p] = request.form[p]

    if request.form['dhcp_interface'] and \
            old_dhcp_interface != request.form['dhcp_interface']:
        record_interface(request.form['dhcp_interface'])
        print("Computing network parameters for new interface: {0}".format(
                request.form['dhcp_interface']))
        nparams = get_subnet_details(request.form['dhcp_interface'])
        for p in nparams:
            params[p] = nparams[p]

    if entry:
        for p in params:
            if params[p]:
                setattr(entry, p, params[p])
    else:
        entry = DhcpSubnet(**params)
        db.session.add(entry)

    db.session.commit()
    flash('Subnet details updated')

    if write_dhcpd_conf():
        launch()

    return redirect(url_for('show_entries', _anchor='dhcp'))

@application.route('/onie', methods=['POST'])
def configure_onie():
    entry = PnCloudAccount.get()
    username = request.form['username']
    password = encrypt_password(request.form['password'])
    if entry:
        if request.form['username']:
            entry.username = username
        if request.form['password']:
            entry.password = password
    else:
        entry = PnCloudAccount(username=username, password=password)
        db.session.add(entry)

    db.session.commit()

    pnc = PnCloud.get()
    pnc.logout()

    flash('PN Cloud details updated')
    return redirect(url_for('show_entries', _anchor='pnc'))

@application.route('/ansible', methods=['POST'])
def configure_ansible():
    entry = AnsibleConfig.get()
    username = request.form['ssh_user']
    password = encrypt_password(request.form['ssh_pass'])
    if entry:
        if request.form['ssh_user']:
            entry.ssh_user = username
        if request.form['ssh_pass']:
            entry.ssh_pass = password
    else:
        entry = AnsibleConfig(ssh_user=username, ssh_pass=password)
        db.session.add(entry)

    db.session.commit()
    flash('Ansible config updated')
    return redirect(url_for('show_entries', _anchor='ansible'))

@application.route('/add', methods=['POST'])
def add_entry():
    msg = ''
    try:
        entry = DhcpClient(hostname=request.form['hostname'],
                           ip=request.form['ip'],
                           mac=request.form['mac'],
                           device_id=request.form['device_id'],
                           device_type=request.form['device_type'],
                           default_url=request.form['default_url'],
                           tag='leaf')
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        print(str(e))
        flash("Error adding DHCP host")
        return redirect(url_for('show_entries', _anchor='dhcp'))

    if write_dhcpd_conf():
        launch()

    msg = 'Host added'

    # Activate host
    if entry.device_id and entry.device_type:
        try:
            pnc = PnCloud.get()
            pnc.login()
            result = pnc.activate_device_id(entry.device_id, entry.device_type)
            print(result)
        except Exception as e:
            print("Failed to activate host: {0}: {1}".format(entry.device_id, e))
            msg += " but activation failed"
        else:
            msg += " and activated"

    flash(msg)
    return redirect(url_for('show_entries', _anchor='dhcp'))

@application.route('/activate/<deviceid>,<devicetype>', methods=['GET'])
def activate(deviceid, devicetype):
    result = False
    try:
        pnc = PnCloud.get()
        pnc.login()
        result = pnc.activate_device_id(deviceid, devicetype)
    except Exception as e:
        print("Failed to activate host: {0}: {1}".format(deviceid, e))
        flash("Failed to activate host")
        return redirect(url_for('show_entries', _anchor='dhcp'))

    if result:
        flash("Activated host")
    else:
        flash("Failed to activate host")

    return redirect(url_for('show_entries', _anchor='dhcp'))

@application.route('/remove/<int:entry_id>', methods=['GET'])
def remove_entry(entry_id):
    entry = DhcpClient.query.filter_by(id=entry_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Removed switch entry")
    else:
        flash("Switch does not exist")

    return redirect(url_for('show_entries', _anchor='dhcp'))

@application.route('/uploadonie', methods=['GET', 'POST'])
def upload_onie():
    if request.method == 'POST':
        # Upload ONIE installer
        if 'onie_installer' not in request.files:
            flash('File not provided')
            return redirect(url_for('show_entries', _anchor='pnc'))

        onie_installer = request.files['onie_installer']
        if onie_installer.filename == '':
            flash("No file selected")
            return redirect(url_for('show_entries', _anchor='pnc'))

        if not onie_installer.filename.startswith('onie-installer-'):
            flash("Not an ONIE installer: {0}".format(onie_installer.filename))
            return redirect(url_for('show_entries', _anchor='pnc'))

        if not onie_installer:
            flash("Failed to upload ONIE installer")
            return redirect(url_for('show_entries', _anchor='pnc'))

        onie_installer_filename = os.path.basename(onie_installer.filename)
        onie_installer_path = os.path.join(WWW_ROOT, onie_installer_filename)
        print("Uploading ONIE installer to path: {0}".format(onie_installer_path))
        onie_installer.save(onie_installer_path)
        set_default_onie_symlink(onie_installer_filename)

        flash("ONIE installer uploaded")
        return redirect(url_for('show_entries', _anchor='pnc'))
    else:
        return render_template("upload_onie.html")

@application.route('/uploadlic', methods=['GET', 'POST'])
def upload_licences():
    if request.method == 'POST':
        if '10g_license' not in request.files \
                and '40g_license' not in request.files:
            flash("Files not provided")
            return redirect(url_for('show_entries', _anchor='pnc'))

        for lictype, code in (('10g_license', DEVICE_TYPE_10G),
                              ('40g_license', DEVICE_TYPE_40G)):
            if not lictype in request.files:
                continue
            lic = request.files[lictype]
            if lic.filename == '':
                flash("License file not selected")
                return redirect(url_for('show_entries', _anchor='pnc'))

            if not lic:
                flash("Failed to upload license")
                return redirect(url_for('show_entries', _anchor='pnc'))

            lic.save(ACTIVATION_KEY_FILES[code])
            flash("{0} license uploaded".format(code.upper()))

        return redirect(url_for('show_entries', _anchor='pnc'))
    else:
        return render_template("upload_licenses.html")

@application.route('/importcsv', methods=['GET', 'POST'])
def import_csv():
    if request.method == 'POST':
        if 'hosts_csv' not in request.files:
            flash('File not provided')
            return redirect(url_for('show_entries', _anchor='dhcp'))

        hosts_csv = request.files['hosts_csv']
        if hosts_csv.filename == '':
            flash('No file selected')
            return redirect(url_for('show_entries', _anchor='dhcp'))

        if not hosts_csv:
            flash("Failed to upload CSV file")
            return redirect(url_for('show_entries', _anchor='dhcp'))

        try:
            text = hosts_csv.read().decode('ascii')
            lines = text.split("\n")
            reader = csv.DictReader(lines, delimiter=",",
                        fieldnames=("mac", "ip", "hostname", "device_id",
                                "device_type", "default_url", "tag"))
        except Exception as e:
            print(e)
            flash("Failed to load CSV file")
            return redirect(url_for('show_entries', _anchor='dhcp'))

        try:
            for row in reader:
                if not row['tag']:
                    row['tag'] = 'leaf'
                entry = DhcpClient(**row)
                db.session.add(entry)
        except Exception as e:
            print(e)
            flash("Error importing CSV: hostname={0}".format(row['hostname']))
            return redirect(url_for('show_entries', _anchor='dhcp'))

        try:
            db.session.commit()
        except exc.IntegrityError as e:
            print(e)
            err = "DB integrity error"
            m = EX_CSV_IMPORT_DUP_RE.search(str(e))
            if m:
                err = "Duplicate entry in record for host: '{0}'".format(m.group(1))
            flash("Error importing CSV: " + err)
            return redirect(url_for('show_entries', _anchor='dhcp'))
        except Exception as e:
            print(e)
            flash("Error importing CSV: {0}".format(type(e)))
            return redirect(url_for('show_entries', _anchor='dhcp'))

        flash("CSV file imported")

        if write_dhcpd_conf():
            launch()

        return redirect(url_for('show_entries', _anchor='dhcp'))
    else:
        return render_template("import_csv.html")

def generate_dhcpd_conf():
    server = DhcpSubnet.get()
    clients = DhcpClient.query.all()
    mandatory_server_params = ('subnet', 'subnet_mask', 'dhcp_range_start', 'dhcp_range_end',
                               'dhcp_range_end', 'dns_primary', 'gateway')
    mandatory_client_params = ('ip', 'mac')
    for p in mandatory_server_params:
        if not getattr(server, p):
            flash("DHCP subnet configuration incomplete")
            return ''

    for client in clients:
        for p in mandatory_client_params:
            if not getattr(client, p):
                flash("DHCP host configuration incomplete")
                return ''

    return render_template("dhcpd.conf", server=server, clients=clients)

def generate_ansible_hosts_file(switchnames):
    clients = DhcpClient.query.filter(DhcpClient.hostname.in_(switchnames))
    #clients = DhcpClient.query.all()
    if not clients:
        return ''

    ansible = AnsibleConfig.get()
    tags = {}
    for client in clients:
        if client.hostname:
            c = client.hostname
        else:
            c = client.ip
        if not client.tag:
            print("Host has not tag: {0}; ignoring it".format(c))
            continue
        if client.tag not in tags:
            tags[client.tag] = []
        tags[client.tag].append(client)

    return render_template("ansible_hosts.txt", ansible=ansible, tags=tags)

def fetch_online():
    pnc = PnCloud.get()
    pnc.login()
    det = pnc.order_details()
    order_details = {
        DEVICE_TYPE_10G: det[0],
        DEVICE_TYPE_40G: det[1],
    }

    for dtype in ACTIVATION_KEY_FILES:
        if not os.path.isfile(ACTIVATION_KEY_FILES[dtype]):
            pnc.activation_key(order_details[dtype]['id'], ACTIVATION_KEY_FILES[dtype])

    for client in DhcpClient.query.all():
        devid = client.device_id
        details = order_details[client.device_type]

        active = [x for x in details['order_activations'] if x['device_id'] == devid]
        if active:
            print("Device already active: {1} ({0}); activation date: {2}".format(
                client.ip, devid, active[0]['activation_date']))
            continue

        print("Activating device: {1} ({0})".format(client.ip, devid))
        order_id = order_details[client.device_type]['id']
        device = {"order_detail_id": order_id, 
                "device_ids": client.device_id}
        activation = pnc.activate(device)

def write_dhcpd_conf():
    dhcpd_conf = generate_dhcpd_conf()
    if not dhcpd_conf:
        return False
    with open(DHCPD_CONFIG, 'w') as f:
        f.write(dhcpd_conf)
    print("Wrote {0}".format(DHCPD_CONFIG))
    return True

def service_status(servicelist=()):
    p = None
    try:
        p = subprocess.Popen([SUPERVISOR, 'status'], stdout=subprocess.PIPE)
    except FileNotFoundError:
        print("Executable not found: {0}".format(SUPERVISOR))
        return []

    (stdout, stderr) = p.communicate()
    services = []
    for line in stdout.splitlines():
        try:
            (service, status, details) = line.decode('ascii').split(None, 2)
        except:
            continue
        if servicelist and service not in servicelist:
            continue
        services.append({
            'service_id': service,
            'service': SERVICE_NAME_MAP.get(service, service),
            'status': status,
            'details': details
        })
    return services

def supervisor(action, process):
    try:
        return (subprocess.call([SUPERVISOR, action, process]) == 0)
    except FileNotFoundError:
        print("Executable not found: {0}".format(SUPERVISOR))
        return False

def restart_dhcpd():
    supervisor('stop', DHCPD_PROC)
    if not supervisor('start', DHCPD_PROC):
        print("Failed to start dhcpd")
        return False
    return True

@application.route('/downloadkey/<dtype>', methods=['GET'])
def download_activation_key(dtype):
    print("Downloading activation key for type: {0}".format(type))
    download = None
    try:
        pnc = PnCloud.get()
        pnc.login()
        download = pnc.activation_key_download(dtype)
    except Exception as e:
        print(e)
        flash("Failed to download activation key")
        return redirect(url_for('show_entries', _anchor='pnc'))

    if os.path.isfile(ACTIVATION_KEY_FILES[dtype]):
        flash("Downloaded activation key")
    else:
        flash("Error downloading activation key of type '{0}'".format(dtype))
    return redirect(url_for('show_entries', _anchor='pnc'))

@application.route('/downloadonie/<installer>/<version>', methods=['GET'])
def download_onie(installer, version):
    print("Downloading ONIE installer: {0} ({1})".format(installer, version))
    download = None
    try:
        pnc = PnCloud.get()
        pnc.login()
        download = pnc.onie_download(installer, version)
    except Exception as e:
        print(e)
        flash("Failed to download ONIE installer")
        return redirect(url_for('show_entries', _anchor='pnc'))

    if os.path.isfile(download):
        flash("Downloaded installer: {0}".format(installer))
    else:
        flash("Error downloading ONIE installer: {0}".format(installer))

    set_default_onie_symlink(installer)
    return redirect(url_for('show_entries', _anchor='pnc'))

def set_default_onie_symlink(installer):
    definst = os.path.join(WWW_ROOT, installer)
    symlink = os.path.join(WWW_ROOT, 'onie-installer')

    try:
        if os.path.isfile(definst):
            if os.path.islink(symlink):
                os.remove(symlink)
            os.symlink(os.path.basename(definst), symlink)
        else:
            print("ONIE installer not found: {0}".format(installer))
            return False
    except Exception as e:
        print("Failed to set up default ONIE symlink: {0}: {1}".format(installer, e))
        return False

    return True

@application.route('/setdefaultonie', methods=['GET', 'POST'])
def set_default_onie():
    if request.method == 'POST':
        installer = request.form['installer']
        if set_default_onie_symlink(installer):
            flash("Default ONIE installer: {0}".format(installer))
        else:
            flash("Failed to set default ONIE installer")
        return redirect(url_for('show_entries', _anchor='pnc'))
    else:
        onie_installers = [os.path.basename(x) for x in glob.glob(os.path.join(WWW_ROOT, 'onie-installer-*'))]
        if os.path.islink(ONIE_INSTALLER_PATH):
            current = os.path.basename(os.readlink(ONIE_INSTALLER_PATH))
        else:
            current = ''
        return render_template("set_default_onie.html", onie_installers=onie_installers, current=current)

@application.route('/launch', methods=['GET'])
def launch():
    pnca = PnCloudAccount.get()
    offline_install = True

    if not write_dhcpd_conf():
        flash('Failed to write DHCP config file')
        return redirect(url_for('show_entries', _anchor='dhcp'))

    if not restart_dhcpd():
        flash("Failed to start the DHCP service")
        return redirect(url_for('show_entries', _anchor='dhcp'))

    flash('DHCP/ONIE server launched')
    return redirect(url_for('show_entries', _anchor='dhcp'))

@application.route('/tsharkstart', methods=['GET'])
def tshark_start():
    if not supervisor('start', TSHARK_PROC):
        flash('Failed to start Tshark')
    return redirect(url_for('show_entries', _anchor='logs'))

@application.route('/tsharkstop', methods=['GET'])
def tshark_stop():
    if not supervisor('stop', TSHARK_PROC):
        flash('Failed to stop Tshark')
    return redirect(url_for('show_entries', _anchor='logs'))

@application.route('/ansible_do', methods=['GET', 'POST'])
def ansible():
    if request.method == 'GET':
        argsrc = request.args
    else:
        argsrc = request.form
    if 'save-tags' in argsrc:
        return ansible_tags()
    else:
        return ansible_hosts()

def ansible_tags():
    tags = {}
    for p in request.form:
        if not p.startswith('tag-'):
            continue
        (x, hostname) = p.split('-', 1)
        h = DhcpClient.query.filter_by(hostname=hostname).first()
        if h:
            print("Updating Ansible host tag for {0}".format(hostname))
            h.tag = request.form[p]

    db.session.commit()
    flash("Updated Ansible host tags")
    return redirect(url_for('show_entries', _anchor='ansible'))

def ansible_hosts():
    if request.method == 'GET':
        argsrc = request.args
    else:
        argsrc = request.form
    switches = argsrc.getlist('switch')
    if not switches:
        flash("No switches selected")
        return redirect(url_for('show_entries', _anchor='ansible'))

    print("Generating Ansible hosts file for: {0}".format(switches))
    hosts = generate_ansible_hosts_file(switches)
    if not hosts:
        flash("Faled to generate Ansible hosts file")
        return redirect(url_for('show_entries', _anchor='ansible'))

    filename = '{:%Y-%m-%d-%H%M%S}.txt'.format(datetime.datetime.now())
    hostsfile = os.path.join(ANSIBLE_HOSTS_LIST, filename)
    with open(hostsfile, 'w') as f:
        f.write(hosts)

    switchlist = ', '.join(sorted(switches))
    entry = AnsibleHostsFile(filename=filename, hosts=switchlist)
    db.session.add(entry)
    db.session.commit()

    return Response(
            hosts,
            mimetype='text/plain',
            headers={"Content-disposition":
                     "attachment; filename=hosts"})

@application.route('/logevents', methods=['GET'])
def log_events():
    events = []
    if os.path.isfile(NGINX_ACCESS_LOG):
        with open(NGINX_ACCESS_LOG) as f:
            for line in f.readlines():
                m = NGINX_ACCESS_LOG_RE.search(line)
                if m:
                    events.append(m.groupdict())

    return render_template('log_events.html', events=reversed(events))

@application.route('/tsharklog', methods=['GET'])
def tshark_log():
    log = ''
    if os.path.isfile(TSHARK_LOG):
        with open(TSHARK_LOG) as f:
            log = f.read()

    return render_template('tshark_log.html', log=log)

@application.route('/techsupport', methods=['GET'])
def techsupport():
    p = subprocess.Popen([TECH_SUPPORT_ARCHIVER, TECH_SUPPORT_ARCHIVE_DIR],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (stdout, stderr) = p.communicate()
    for line in stdout.splitlines():
        line = line.decode('ascii')
        m = TECH_SUPPORT_ARCHIVE_RE.search(line)
        if m:
            archive = os.path.join(TECH_SUPPORT_ARCHIVE_DIR,
                    os.path.basename(m.group(1)))
            return send_file(archive, as_attachment=True)
        else:
            print(line)

    flash("Failed to generate tech support bundle")
    return redirect(url_for('show_entries', _anchor='logs'))

@application.cli.command()
def dhcpsetup():
    """Launches the DHCP service"""
    subnet = DhcpSubnet.get()
    if subnet.dhcp_interface and not os.path.isfile(DHCP_INTERFACE_NAME):
        click.echo("Recording DHCP interface")
        record_interface(subnet.dhcp_interface)

    running = True
    for x in range(10):
        status = service_status((DHCPD_PROC,))
        if status:
            running = (status[0]['status'] == 'RUNNING')
            break
        time.sleep(1)

    if not running:
        if write_dhcpd_conf():
            click.echo("Starting DHCP service")
            supervisor('start', DHCPD_PROC)
        else:
            click.echo("Failed to generate DHCP config")

if __name__ == "__main__":
    application.run(host='0.0.0.0')
