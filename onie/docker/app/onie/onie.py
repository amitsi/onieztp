import os
import re
import requests
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
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

DEVICE_TYPE_10G = '10g'
DEVICE_TYPE_40G = '40g'

ACTIVATION_KEY_FILES = {
    DEVICE_TYPE_10G: '/tmp/license_10g.activationkey',
    DEVICE_TYPE_40G: '/tmp/license_40g.activationkey',
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

    clients = db.relationship("DhcpClient")

class OnieInstaller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    onie_version = db.Column(db.String(40), nullable=True)
    username = db.Column(db.String(40), nullable=True)
    password = db.Column(db.String(40), nullable=True)

#
# VIEWS
#

@application.route('/')
def show_entries():
    server = DhcpSubnet.query.all()
    if server:
        server = server[0]
    clients = DhcpClient.query.all()
    onie = OnieInstaller.query.all()
    if onie:
        onie = onie[0]
    return render_template('show_entries.html', server=server,
            entries=clients, onie=onie)

@application.route('/confsubnet', methods=['POST'])
def configure_subnet():
    entries = DhcpSubnet.query.all()
    if entries:
        entry = entries[0]
        for p in [ 'subnet', 'subnet_mask', 'dhcp_range_start',
                   'dhcp_range_end', 'dns_primary', 'dns_secondary',
                   'domain_name', 'gateway', 'broadcast_address' ]:
            if request.form[p]:
                setattr(entry, p, request.form[p])
    else:
        entry = DhcpSubnet(subnet=request.form['subnet'],
                           subnet_mask=request.form['subnet_mask'],
                           dhcp_range_start=request.form['dhcp_range_start'],
                           dhcp_range_end=request.form['dhcp_range_end'],
                           dns_primary=request.form['dns_primary'],
                           dns_secondary=request.form['dns_secondary'],
                           domain_name=request.form['domain_name'],
                           gateway=request.form['gateway'],
                           broadcast_address=request.form['broadcast_address'])
        db.session.add(entry)

    db.session.commit()
    flash('Subnet details updated')
    return redirect(url_for('show_entries'))

@application.route('/onie', methods=['POST'])
def configure_onie():
    entries = OnieInstaller.query.all()
    if entries:
        entry = entries[0]
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

@application.route('/launch', methods=['GET'])
def launch():
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


    flash('DHCP/ONIE server launched')
    return redirect(url_for('show_entries'))

if __name__ == "__main__":
    application.run(host='0.0.0.0')
