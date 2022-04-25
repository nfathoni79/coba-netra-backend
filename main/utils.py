from hashlib import sha1
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# import codecs
import requests


PLAINTEXT = 'budi'
SECRET = '1234'
CIPHERTEXT = 'vpOv+CMTfv3FzzTSUugEnQ=='
HEX = '76704f762b434d54667633467a7a5453557567456e513d3d'

BASE_URL = 'https://pdev.netra.space'
AUTH_URL = BASE_URL + '/auth'
FROM_DEV_URL = BASE_URL + '/data/fromDevice'
TO_DEV_URL = BASE_URL + '/data/toDevice'
TO_DEV_GET_URL = BASE_URL + '/data/toDevice/message'
DEV_LIST_URL = BASE_URL + '/data/devices'
SEARCH_DEV_URL = BASE_URL + '/data/device'

TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYmhla3RpQGZpc2hvbi5jb20iLCJpYXQiOjE2NTAyNzQ0MjQsImV4cCI6MTY1MDM2MDgyNH0.kIt0N0NO6uMdSCnBDXpZPqzYmR8CKyixpsmMvaVgdRo'
DEV_ID = '300534060028740'
PAYLOAD = 'coba message'

ANIME_BASE_URL = 'https://animechan.vercel.app'
ANIME_QUOTE_URL = ANIME_BASE_URL + '/api/random'


def encrypt(plaintext=PLAINTEXT, secret=SECRET):
    key = sha1(secret.encode('utf-8')).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    plainbyte = pad(plaintext.encode('utf-8'), 16)
    cipherbyte = cipher.encrypt(plainbyte)
    cipherbyte_b64 = b64encode(cipherbyte)
    return str(cipherbyte_b64, encoding='utf-8')


def decrypt(ciphertext=CIPHERTEXT, secret=SECRET):
    key = sha1(secret.encode('utf-8')).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    cipherbyte = b64decode(ciphertext)
    plainbyte = unpad(cipher.decrypt(cipherbyte), 16)
    return str(plainbyte, encoding='utf-8')


def string_to_hex(string: str = CIPHERTEXT):
    return string.encode('utf-8').hex()


def hex_to_string(hex=HEX):
    # hexbytes = bytes(hex, encoding='utf-8')
    # binstring = codecs.decode(hexbytes, encoding='hex')
    # return str(binstring, encoding='utf-8')

    return bytes.fromhex(hex).decode('utf-8')


def hex_decrypt(hex_cipher=HEX, secret=SECRET):
    ciphertext = hex_to_string(hex_cipher)
    plaintext = decrypt(ciphertext, secret)
    return plaintext


def get_random_quote():
    response = requests.get(ANIME_QUOTE_URL, verify=False)
    res_json = response.json()

    try:
        anime = res_json['anime']
        character = res_json['character']
        quote = res_json['quote']

        return f'Anime: {anime}. Character: {character}. Quote: {quote}.'
    except Exception as e:
        print(e)

    return None


def auth(username, password):
    headers = {'Content-Type': 'application/json'}
    data = {'username': username, 'password': password}

    response = requests.post(
        AUTH_URL, headers=headers, data=data, verify=False)
    response_json = response.json()

    try:
        data = response_json['data']
        return data
    except Exception as e:
        print(e)

    return None


def get_from_dev(dev_id=DEV_ID, from_date='', to_date='', gps=False):
    headers = {'Authorization': f'Bearer {TOKEN}'}
    body = {
        'deviceId': dev_id,
        'from': from_date,
        'end': to_date,
        'gps': gps,
    }

    response = requests.post(
        FROM_DEV_URL, headers=headers, json=body, verify=False)

    if response.status_code == 200:
        res_json = response.json()

        try:
            success = res_json['success']
            if success:
                messages = res_json.get('data', [])
                gps_list = res_json.get('gps', [])
                return {
                    'messages': messages,
                    'gps_list': gps_list,
                }
            else:
                return res_json
        except Exception as e:
            print(e)
            return {'error': e}

    return {
        'status': response.status_code,
        'content': response.content.decode(),
    }


def send_to_dev(dev_id=DEV_ID, payload=PAYLOAD, type='text'):
    headers = {'Authorization': f'Bearer {TOKEN}'}
    body = {
        'deviceId': dev_id,
        'payload': payload,
        'type': type,
    }

    response = requests.post(
        TO_DEV_URL, headers=headers, json=body, verify=False)

    if response.status_code == 200:
        res_json = response.json()
        return {'result': res_json}

    return {
        'status': response.status_code,
        'content': response.content.decode(),
    }


def get_to_dev_sent(dev_id=DEV_ID, from_date='', to_date=''):
    headers = {
        'Authorization': f'Bearer {TOKEN}',
        'deviceId': dev_id,
    }

    response = requests.get(
        f'{TO_DEV_GET_URL}?from={from_date}&end={to_date}',
        headers=headers, verify=False)

    if response.status_code == 200:
        res_json = response.json()
        return {'result': res_json}

    return {
        'status': response.status_code,
        'content': response.content.decode(),
    }


def get_dev_list():
    headers = {'Authorization': f'Bearer {TOKEN}'}

    response = requests.get(DEV_LIST_URL, headers=headers, verify=False)

    if response.status_code == 200:
        res_json = response.json()

        try:
            success = res_json['success']
            if success:
                return {'devices': res_json['data']}
            else:
                return res_json
        except Exception as e:
            print(e)
            return {'error': e}

    return {
        'status': response.status_code,
        'content': response.content.decode(),
    }


def search_dev(terms='coba'):
    headers = {'Authorization': f'Bearer {TOKEN}'}
    body = {
        'terms': terms,
    }

    response = requests.post(
        SEARCH_DEV_URL, headers=headers, json=body, verify=False)

    if response.status_code == 200:
        res_json = response.json()
        success = res_json['success']

        if success:
            return {'devices': res_json['data']}
        else:
            return res_json

    return {
        'status': response.status_code,
        'content': response.content.decode(),
    }
