import json
import pathlib

from fido_u2f import registration, verification
from flask import Flask, redirect, request, session

from .tables import Device, User, db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'WebAuthN would be nice one day.'
app.config['DEBUG'] = True

db.init_app(app)


@app.before_first_request
def _():
    db.create_all()


class U2FManager(registration.U2FRegistrationManager, verification.U2FSigningManager):

    def __init__(self):
        self.app_id = 'https://localhost:5000'

    def create_device_registration_model(self, *, transports, **kwargs):
        device = Device()
        device.u2f_transports = transports
        for k, v in kwargs.items():
            setattr(device, k, v)
        db.session.add(device)
        db.session.commit()
        return device

    def update_device_registration_counter(self, device, counter):
        device.counter = counter
        return device


u2f_manager = U2FManager()


@app.route("/")
def hello():
    dat = '<table>'
    dat += '<tr><th>Username</th><th>Registered keys</th></tr>'
    for user in User.query.all():
        dat += '<tr><td>' + user.name + '</td><td><table>\n'
        dat += '<tr><th>Index</th><th>Key Handle</th><th>Counter</th></tr>\n'
        for idx, key in enumerate(user.devices):
            dat += '<tr><td>{0}</td><td>{1.key_handle}</td><td>{1.counter}</td></tr>\n'.format(
                idx, key)
        dat += '</table></td></tr>'
    dat += '</table>'

    pre = ''
    if request.args.get('login', None) == 'success':
        pre = '<h1>You logged in successfully!!!!!!!!!!!!!!!</h1>'

    return pre + """
    <form method='POST' action='/register' >
    <input type='text' name='name' value='admin' />
    <input type='submit' value='Register new Device' />
    </form>
    <form method='POST' action='/login' >
    <input type='text' name='name' value='admin' />
    <input type='submit' value='Verify registered device' />
    </form>
    """ + dat


@app.route("/register.js", methods=['GET'])
def get_register_js():
    return (pathlib.Path(__file__).parent / 'register.js').open('r').read()


@app.route("/register", methods=['POST'])
def do_register_start():
    user_name = request.form['name']
    session['user_name'] = user_name
    user = User.query.filter_by(name=user_name).first()
    if not user:
        user = User(name=user_name)
        db.session.add(user)
        db.session.commit()
    data = u2f_manager.create_registration_challenge(session, user.devices)

    js = """
    const appId = {appId};
    const registerRequests = {registerRequests};
    const registeredKeys = {registeredKeys};
    """.format(
        appId=json.dumps(data['appId']),
        registerRequests=json.dumps(data['registerRequests']),
        registeredKeys=json.dumps(data['registeredKeys'])
    )
    return (
        '<pre>' + js + '</pre><script>' + js + '</script>' +
        '<span id="u2f_status">Loading</span><br /><a href="/">Back</a>' +
        '<form id="u2f_data" method="POST" action="/register2">' +
        '<input name="data" id="data" />' +
        '</form>'
        '<script src="register.js"></script>'
    )


@app.route("/register2", methods=['POST'])
def do_register_verify():
    user_name = session['user_name']
    user = User.query.filter_by(name=user_name).first()
    if not user:
        return 'No user by that name; <a href="/">Back</a>'
    data = request.json or json.loads(request.form['data'])
    device = u2f_manager.process_registration_response(
        session, data
    )
    device.user = user
    db.session.commit()
    return redirect('/')


@app.route("/login.js", methods=['GET'])
def get_login_js():
    return (pathlib.Path(__file__).parent / 'login.js').open('r').read()


@app.route("/login", methods=['POST'])
def do_login_start():
    user_name = request.form['name']
    session.user_name = user_name
    user = User.query.filter_by(name=user_name).first()
    if not user:
        return 'No user by that name; register a device first? <a href="/">Back</a>'
    if not user.devices:
        return 'No devices for that user; register a device first? <a href="/">Back</a>'

    devices = user.devices
    data = u2f_manager.create_signing_challenge(session, devices)
    js = """
    const appId = {appId};
    const challenge = {challenge};
    const registeredKeys = {registeredKeys};
    """.format(
        appId=json.dumps(data['appId']),
        challenge=json.dumps(data['challenge']),
        registeredKeys=json.dumps(data['registeredKeys'])
    )
    return (
        '<pre>' + js + '</pre><script>' + js + '</script>' +
        '<span id="u2f_status">Loading</span><br /><a href="/">Back</a>' +
        '<form id="u2f_data" method="POST" action="/login2">' +
        '<input name="data" id="data" />' +
        '</form>'
        '<script src="login.js"></script>'
    )


@app.route("/login2", methods=['POST'])
def do_login_verify():
    user_name = session['user_name']
    user = User.query.filter_by(name=user_name).first()
    if not user:
        return 'No user by that name; <a href="/">Back</a>'
    data = request.json or json.loads(request.form['data'])
    device = u2f_manager.process_signing_response(
        session, data, user.devices
    )
    db.session.commit()
    return redirect('/?login=success')
