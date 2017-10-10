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

class DhcpServer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return "<DhcpServer {0}>".format(self.hostname)

#
# VIEWS
#

@application.route('/')
def show_entries():
    dhcp_servers = DhcpServer.query.all()
    return render_template('show_entries.html', entries=dhcp_servers)

@application.route('/add', methods=['POST'])
def add_entry():
    entry = DhcpServer(hostname=request.form['hostname'])
    db.session.add(entry)
    db.session.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))

if __name__ == "__main__":
    application.run(host='0.0.0.0')
