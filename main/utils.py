from hashlib import sha1
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# import codecs
import requests


BASE_URL = 'http://example.com'
AUTH_URL = BASE_URL + '/auth'
UP_URL = BASE_URL + '/up'

ANIME_BASE_URL = 'https://animechan.vercel.app'
ANIME_QUOTE_URL = ANIME_BASE_URL + '/api/random'


def encrypt(plaintext, secret):
    key = sha1(secret.encode('utf-8')).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    plainbyte = pad(plaintext.encode('utf-8'), 16)
    cipherbyte = cipher.encrypt(plainbyte)
    cipherbyte_b64 = b64encode(cipherbyte)
    return str(cipherbyte_b64, encoding='utf-8')


def decrypt(ciphertext, secret):
    key = sha1(secret.encode('utf-8')).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    cipherbyte = b64decode(ciphertext)
    plainbyte = unpad(cipher.decrypt(cipherbyte), 16)
    return str(plainbyte, encoding='utf-8')


def string_to_hex(string: str):
    return string.encode('utf-8').hex()


def hex_to_string(hex):
    # hexbytes = bytes(hex, encoding='utf-8')
    # binstring = codecs.decode(hexbytes, encoding='hex')
    # return str(binstring, encoding='utf-8')

    return bytes.fromhex(hex).decode('utf-8')


def get_random_quote():
    response = requests.get(ANIME_QUOTE_URL, verify=False)
    response_json = response.json()

    try:
        anime = response_json['anime']
        character = response_json['character']
        quote = response_json['quote']

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


def get_up(token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    data = {}

    response = requests.get(UP_URL, headers=headers, data=data, verify=False)
    response_json = response.json()

    try:
        data = response_json['data']
        return data
    except Exception as e:
        print(e)

    return None
