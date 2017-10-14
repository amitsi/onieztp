from netaddr import IPNetwork
import os
import re
import requests
import subprocess
import sqlite3
from flask import Flask, Response, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_sqlalchemy import SQLAlchemy

DEBUG = os.environ.get('FLASK_DEBUG', False)
if DEBUG == 'false':
    DEBUG = False

application = Flask(__name__) # create the application instance :)
application.config.from_object(__name__) # load config from this file , onie.py

requests.packages.urllib3.disable_warnings() # FIXME

# Load default config and override config from an environment variable
application.config.update(dict(
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(application.root_path, 'onie.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=True,
    SECRET_KEY='secret',
    USERNAME='admin',
    PASSWORD='test123'
))
application.config.from_envvar('ONIE_SETTINGS', silent=True)
db = SQLAlchemy(application)

#
# UTILS
#

PNC_LOGIN = 'https://cloud-web.pluribusnetworks.com/api/login'
PNC_ORDER_DETAILS = 'https://cloud-web.pluribusnetworks.com/api/orderDetails'
PNC_ORDER_ACTIVATION = 'https://cloud-web.pluribusnetworks.com/api/orderActivations'
PNC_ACTIVATION_KEY_FOR = 'https://cloud-web.pluribusnetworks.com/api/offline_bundle/{0}'.format

WWW_ROOT = '/var/www/html/images'
ONIE_INSTALLER_PATH = os.path.join(WWW_ROOT, 'onie-installer')
LICENCE_PATH_10G = os.path.join(WWW_ROOT, 'license_10g/onvl-activation-keys')
LICENCE_PATH_40G = os.path.join(WWW_ROOT, 'license_40g/onvl-activation-keys')

DEVICE_TYPE_10G = '10g'
DEVICE_TYPE_40G = '40g'

IP_ADDR_RE = re.compile(r'^\s*inet ([\d\.]+/\d{1,2})')

DHCPD_CONFIG = '/etc/dhcp/dhcpd.conf'
ACTIVATION_KEY_FILES = {
    DEVICE_TYPE_10G: os.path.join(WWW_ROOT, 'license_10g/onvl-activation-keys'),
    DEVICE_TYPE_40G: os.path.join(WWW_ROOT, 'license_40g/onvl-activation-keys'),
}

SUPERVISOR = 'supervisorctl'
DHCPD_PROC = 'dhcpd'

DEFAULTS = {
    'DhcpSubnet': {
        'subnet': '10.9.0.0',
        'subnet_mask': '255.255.0.0',
        'dhcp_interface': 'eth0',
        'dhcp_range_start': '10.9.31.142',
        'dhcp_range_end': '10.9.31.149',
        'dns_primary': '10.9.10.1',
        'dns_secondary': '10.20.4.1',
        'domain_name': 'pluribusnetworks.com',
        'gateway': '10.9.9.1',
        'broadcast_address': '10.9.255.255',
    },
    'OnieInstaller': {
        'onie_version': '2.6.1-2060112059',
    },
    'DhcpClient': [
    ],
}

class PnCloud:
    __instance = None

    def __init__(self):
        self.session = requests.Session()
        self.logged_in = False
        self.session.verify = False  # FIXME
        self.username = None
        self.full_name = None

    @classmethod
    def get(klass):
        if not klass.__instance:
            klass.__instance = klass()
        return klass.__instance

    def get_onie_details(self):
        onie = OnieInstaller.query.all()
        if onie:
            return onie[0]
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
            raise Exception("ERROR: {0} {1}".format(r.status_code, r.text))

    def _api_post(self, url, data={}):
        if 'csrfmiddlewaretoken' not in data and 'csrftoken' in self.session.cookies:
            print("Adding CSRF token to request: {0}".format(url))
            data['csrfmiddlewaretoken'] = self.session.cookies['csrftoken']
        return self._api_request(self.session.post, url, data)

    def _api_get(self, url):
        return self._api_request(self.session.get, url)

    def login(self):
        if not self.logged_in:
            print("Logging in to PN cloud")
            onie = self.get_onie_details()
            if not onie:
                print("ONIE details not configured")
                return False

            data = {"login_email": onie.username, "login_password": onie.password}
            resp = self._api_post(PNC_LOGIN, data)
            self.logged_in = resp.get('success', False)
            if self.logged_in:
                self.username = resp.get('username', '')
                self.full_name = resp.get('full_name', '')

        if self.logged_in:
            print("Logged in as user: {0} ({1})".format(self.username,
                self.full_name))
        else:
            print("Failed to log in as user: {0}".format(onie.username))

        return self.logged_in

    def order_details(self):
        if not self.logged_in:
            print("Not logged in")
            return False

        order_det = self._api_get(PNC_ORDER_DETAILS)
        return order_det.get('order_details', [])

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

    server_id = db.Column(db.Integer, db.ForeignKey('dhcp_subnet.id'))

    def __repr__(self):
        return "<DhcpClient {0}>".format(self.hostname)

class DhcpSubnet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subnet = db.Column(db.String(40), nullable=False)
    subnet_mask = db.Column(db.String(40), nullable=False)
    dhcp_range_start = db.Column(db.String(40), nullable=False)
    dhcp_range_end = db.Column(db.String(40), nullable=False)
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
        return IPNetwork(myip)

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

        print("Server IP: \"{0}\"".format(myip))
        return myip

    @property
    def server_port(self):
        return int(os.environ.get('HTTP_PORT', '5000'))

    @property
    def onie_url(self):
        if self.default_url:
            return self.default_url
        return "http://{0}:{1}/images/onie-installer".format(self.server_ip.ip, self.server_port)

class OnieInstaller(db.Model):
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

#
# VIEWS
#

@application.route('/')
def show_entries():
    server = DhcpSubnet.get()
    clients = DhcpClient.query.all()
    onie = OnieInstaller.get()
    ansible = AnsibleConfig.get()
    return render_template('show_entries.html', server=server,
            entries=clients, onie=onie, ansible=ansible)

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
        print("Computing network parameters")
        ip = DhcpSubnet.ip_for_interface(request.form['dhcp_interface'])
        params['subnet'] = str(ip.network)
        params['subnet_mask'] = str(ip.netmask)
        params['broadcast_address'] = str(ip.broadcast)

    if entry:
        for p in params:
            if params[p]:
                setattr(entry, p, params[p])
    else:
        entry = DhcpSubnet(**params)
        db.session.add(entry)

    db.session.commit()
    flash('Subnet details updated')
    return redirect(url_for('show_entries'))

@application.route('/onie', methods=['POST'])
def configure_onie():
    entry = OnieInstaller.get()
    if entry:
        for p in ['onie_version', 'username', 'password']:
            if request.form[p]:
                setattr(entry, p, request.form[p])
    else:
        entry = OnieInstaller(onie_version=request.form['onie_version'],
                              username=request.form['username'],
                              password=request.form['password'])
        db.session.add(entry)

    db.session.commit()
    flash('ONIE details updated')
    return redirect(url_for('show_entries'))

@application.route('/ansible', methods=['POST'])
def configure_ansible():
    entry = AnsibleConfig.get()
    if entry:
        for p in ['ssh_user', 'ssh_pass']:
            if request.form[p]:
                setattr(entry, p, request.form[p])
    else:
        entry = AnsibleConfig(ssh_user=request.form['ssh_user'],
                              ssh_pass=request.form['ssh_pass'])
        db.session.add(entry)

    db.session.commit()
    flash('Ansible config updated')
    return redirect(url_for('show_entries'))

@application.route('/add', methods=['POST'])
def add_entry():
    entry = DhcpClient(hostname=request.form['hostname'],
                       ip=request.form['ip'],
                       mac=request.form['mac'],
                       tag=request.form['tag'],
                       device_id=request.form['device_id'],
                       device_type=request.form['device_type'])
    db.session.add(entry)
    db.session.commit()
    flash('Host added')
    return redirect(url_for('show_entries'))

@application.route('/remove/<int:entry_id>', methods=['GET'])
def remove_entry(entry_id):
    entry = DhcpClient.query.filter_by(id=entry_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Removed switch entry")
    else:
        flash("Switch does not exist")

    return redirect(url_for('show_entries'))

@application.route('/uploadonie', methods=['GET', 'POST'])
def upload_onie():
    if request.method == 'POST':
        # Upload ONIE installer
        if 'onie_installer' not in request.files:
            flash('File not provided')
            return redirect(url_for('show_entries'))

        onie_installer = request.files['onie_installer']
        if onie_installer.filename == '':
            flash("No file selected")
            return redirect(url_for('show_entries'))

        if not onie_installer:
            flash("Failed to upload ONIE installer")
            return redirect(url_for('show_entries'))

        onie_installer.save(ONIE_INSTALLER_PATH)
        flash("ONIE installer uploaded")
        return redirect(url_for('show_entries'))
    else:
        return render_template("upload_onie.html")

@application.route('/uploadlic', methods=['GET', 'POST'])
def upload_licences():
    if request.method == 'POST':
        if '10g_license' not in request.files \
                or '40g_license' not in request.files:
            flash("Files not provided")
            return redirect(url_for('show_entries'))

        licence_10g = request.files['10g_license']
        licence_40g = request.files['40g_license']
        if licence_10g.filename == '' or licence_40g.filename == '':
            flash("Licence files not selected")
            return redirect(url_for('show_entries'))

        if not licence_10g or not licence_40g:
            flash("Failed to upload licences")
            return redirect(url_for('show_entries'))

        licence_10g.save(ACTIVATION_KEY_FILES[DEVICE_TYPE_10G])
        licence_40g.save(ACTIVATION_KEY_FILES[DEVICE_TYPE_40G])
        flash("Licenses uploaded")
        return redirect(url_for('show_entries'))
    else:
        return render_template("upload_licenses.html")

def generate_dhcpd_conf():
    server = DhcpSubnet.get()
    clients = DhcpClient.query.all()
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

def launch_online():
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

@application.route('/launch', methods=['GET'])
def launch():
    onie = OnieInstaller.get()
    offline_install = True

    if not os.path.isfile(ONIE_INSTALLER_PATH):
        print("ONIE installer not available locally")
        if not onie or not onie.onie_version:
            flash("ONIE version not specified")
            return redirect(url_for('show_entries'))
        offline_install = False

    for f in ACTIVATION_KEY_FILES.values():
        if not os.path.isfile(f):
            print("Activation key not found: {0}".format(f))
            offline_install = False

    if not offline_install:
        print("Online setup")
        raise Exception("Onine ONIE setup not implemented yet") # XXX: FIXME

    if not write_dhcpd_conf():
        flash('Failed to write DHCHD config file')
        return redirect(url_for('show_entries'))

    if not restart_dhcpd():
        flash("Failed to start the DHCP service")
        return redirect(url_for('show_entries'))

    flash('DHCP/ONIE server launched')
    return redirect(url_for('show_entries'))

@application.route('/ansiblehosts', methods=['GET', 'POST'])
def ansible_hosts():
    if request.method == 'GET':
        argsrc = request.args
    else:
        argsrc = request.form
    switches = argsrc.getlist('switch')
    if not switches:
        flash("No switches selected")
        return redirect(url_for('show_entries'))

    print("Generating Ansible hosts file for: {0}".format(switches))
    hosts = generate_ansible_hosts_file(switches)
    if not hosts:
        flash("Faled to generate Ansible hosts file")
        return redirect(url_for('show_entries'))

    return Response(
            hosts,
            mimetype='text/plain',
            headers={"Content-disposition":
                     "attachment; filename=hosts"})

if __name__ == "__main__":
    application.run(host='0.0.0.0')
