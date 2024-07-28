from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app as app
)
import os
import hashlib
import urllib.parse

bp = Blueprint('lab', __name__)

INVALID_KEY = '-1'


@bp.route('/')
def main():
    uid = request.args.get('uid', default=None)
    if not uid:
        return 'UID argument not found. Aborting.'
    app.logger.info('Request received from user %s', uid)

    cmd = get_command()
    app.logger.info(request.args.get('lstcmd').encode('utf-8', 'surrogateescape'))
    download = request.args.get('download', default='', type=str)
    mac = request.args.get('mac', default='', type=str)
    my_name = request.args.get('myname', default='', type=str)

    if not my_name:
        return 'Please include the "myname" argument in the request'

    if not cmd or not mac:
        return 'Please specify a command and its MAC'

    key = find_key(uid)
    if key == INVALID_KEY:
        return 'No key found for this user ' + uid
    valid = verify_mac(key, my_name, uid, cmd, download, mac)
    if not valid:
        return render_template('index.html', valid=False)

    files = []
    if cmd == '1':
        files = list_files()
    content = ''
    if download:
        content = read_file(download)
    return render_template('index.html', valid=True, files=files, content=content)


@bp.route('/generate_mac')
def generate_mac_endpoint():
    my_name = request.args.get('myname', default=None)
    uid = request.args.get('uid', default=None)
    cmd = request.args.get('lstcmd', default=None)
    download = request.args.get('download', default='')

    key = find_key(uid)
    if key == INVALID_KEY:
        return 'No key found for this user ' + uid

    if not key or not my_name or not uid or not cmd:
        return 'Missing required parameters'

    mac = generate_mac(key, my_name, uid, cmd, download)
    return f'Generated MAC: {mac}'


def generate_mac(key, my_name, uid, cmd, download=''):
    download_message = '' if not download else '&download=' + download
    message = ''
    if my_name:
        message = 'myname={}&'.format(my_name)
    message += 'uid={}&lstcmd='.format(uid) + cmd + download_message
    payload = key + ':' + message
    real_mac = hashlib.sha256(payload.encode('utf-8', 'surrogateescape')).hexdigest()
    return real_mac


def find_key(uid):
    print("Here"+app.config['LAB_HOME_DIR'])
    path = app.config['LAB_HOME_DIR'] + '/' + app.config['KEY_FILE_NAME']
    if not os.path.exists(path):
        app.logger.error('key file cannot be found')
        return INVALID_KEY
    with open(path, 'r') as f:
        lines = f.readlines()
    app.logger.debug(path)
    app.logger.debug(lines)
    for line in lines:
        line = line.strip()
        app.logger.debug(line)
        delimiter = app.config['KEY_FILE_DELIMITER']
        if delimiter not in line:
            app.logger.error('invalid line in the key file [delimiter not found]' + line)
            continue
        _uid, _key = line.split(delimiter)
        if _uid == uid:
            return _key
    return INVALID_KEY


def verify_mac(key, my_name, uid, cmd, download, mac):
    download_message = '' if not download else '&download=' + download
    message = ''
    if my_name:
        message = 'myname={}&'.format(my_name)
    message += 'uid={}&lstcmd='.format(uid) + cmd + download_message
    payload = key + ':' + message
    app.logger.debug('payload is [{}]'.format(payload))
    real_mac = hashlib.sha256(payload.encode('utf-8', 'surrogateescape')).hexdigest()
    app.logger.debug('real mac is [{}]'.format(real_mac))
    if mac == real_mac:
        return True
    return False


def list_files():
    return os.listdir(app.config['LAB_HOME_DIR'])


def read_file(file):
    path = app.config['LAB_HOME_DIR'] + '/' + file
    if not path_access_control(path):
        return 'Access Denied'
    if not os.path.exists(path):
        return 'No Such File [{}]'.format(file)
    result = []
    with open(path, 'r') as f:
        lines = f.readlines()
    for line in lines:
        result.append(line.strip())
    return result


def get_command():
    query = request.query_string.decode('utf-8', 'surrogateescape')
    if '%' in query:
        query = urllib.parse.unquote(query, errors="surrogateescape")
    pairs = query.split('&')
    for pair in pairs:
        key, value = pair.split('=')
        if key == 'lstcmd':
            return value
    return ''


def path_access_control(path):
    normalized = os.path.normpath(path)
    return os.path.commonprefix([normalized, app.config['LAB_HOME_DIR']]) == app.config['LAB_HOME_DIR']



def extend_hash(mac, original_message, append):
    key_length = 16  # You need to know the original key length
    new_key_length = len(mac) // 2  # Convert the MAC from hex to bytes

    # Convert hex MAC to bytes
    mac_bytes = bytes.fromhex(mac)
    
    # Perform hash extension attack
    new_mac, new_message = hashpumpy.hashpump(mac_bytes, original_message.encode(), append.encode(), key_length)
    
    # Return the new MAC and message
    return new_mac.hex(), new_message.decode()

@app.route('/extend_hash', methods=['GET'])
def extend_hash_endpoint():
    mac = request.args.get('mac')
    original_message = request.args.get('original_message')
    append = request.args.get('append')
    
    if not mac or not original_message or not append:
        return jsonify({'error': 'Missing parameters'}), 400
    
    try:
        new_mac, new_message = extend_hash(mac, original_message, append)
        return jsonify({
            'new_mac': new_mac,
            'new_message': new_message
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500