import json
import hashlib
import hmac
import requests
from loguru import logger
from datetime import datetime
import argparse


parser = argparse.ArgumentParser(usage=' python3 delete_chat.py --id {channel id} --secret {channel secret_key } --amojo {account amojo_id}')
parser.add_argument('--id', help='channel id')
parser.add_argument('--secret', help='channel secret key')
parser.add_argument('--amojo', help='account amojo_id')
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()

path = f'/v2/origin/custom/{args.id}/disconnect'
url = f'https://amojo.amocrm.ru{path}'
logger.debug(f'[+] url: {url}')
payload = {'account_id': args.amojo}
logger.debug(f'[+] payload: {payload}')
payload = json.dumps(payload)
checkSum = hashlib.md5(payload.encode()).hexdigest()
method: str = 'DELETE'
contentType = 'application/json'
date: str = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

sign = "\n".join([
    method,
    checkSum,
    contentType,
    date,
    path
])

signature = hmac.new(args.secret.encode(), sign.encode(), hashlib.sha1).hexdigest()
logger.debug(signature)
headers = {
    'Date': date,
    'Content-Type': contentType,
    'Content-MD5': checkSum,
    'X-Signature': signature
}

logger.debug(f'headers: {headers}')

logger.info('Trying to request...')

request = requests.delete(url, headers=headers, data=payload)

if request.status_code == 200:
    logger.success(request.status_code)
else:
    logger.error(f'error: {request.status_code, request.content}')
