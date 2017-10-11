import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
from flask_sqlalchemy import SQLAlchemy

application = Flask(__name__) # create the application instance :)
application.config.from_object(__name__) # load config from this file , onie.py

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
    default_url = db.Column(db.String(512), nullable=True)
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

#
# VIEWS
#

@application.route('/')
def show_entries():
    server = DhcpSubnet.query.all()
    if server:
        server = server[0]
    clients = DhcpClient.query.all()
    return render_template('show_entries.html', server=server, entries=clients)

@application.route('/confsubnet', methods=['POST'])
def configure_subnet():
    entries = DhcpSubnet.query.all()
    if entries:
        entry = entries[0]
        for p in [ 'subnet', 'subnet_mask', 'dhcp_range_start',
                   'dhcp_range_end', 'dns_primary', 'dns_secondary',
                   'domain_name', 'gateway', 'broadcast_address' ]:
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

@application.route('/add', methods=['POST'])
def add_entry():
    entry = DhcpClient(hostname=request.form['hostname'],
                       ip=request.form['ip'],
                       mac=request.form['mac'],
                       default_url=request.form['default_url'])
    db.session.add(entry)
    db.session.commit()
    flash('Host added')
    return redirect(url_for('show_entries'))

if __name__ == "__main__":
    application.run(host='0.0.0.0')
