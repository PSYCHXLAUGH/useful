import json
import hashlib
import hmac
import requests
from loguru import logger
from datetime import datetime
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(
        usage='python3 delete_chat.py --id {channel id} --secret {channel secret_key} --amojo {account amojo_id}'
    )
    parser.add_argument('--id', required=True, help='Channel ID')
    parser.add_argument('--secret', required=True, help='Channel secret key')
    parser.add_argument('--amojo', required=True, help='Account amojo ID')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def create_signature(method, payload, path, secret):
    check_sum = hashlib.md5(payload.encode()).hexdigest()
    date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    sign_string = "\n".join([method, check_sum, 'application/json', date, path])
    signature = hmac.new(secret.encode(), sign_string.encode(), hashlib.sha1).hexdigest()
    
    return check_sum, date, signature


def make_request(url, headers, payload):
    try:
        response = requests.delete(url, headers=headers, data=payload)
        response.raise_for_status()  # Raise an error for HTTP errors
        return response
    except requests.exceptions.HTTPError as e:
        logger.error(f'HTTP error: {e.response.status_code} - {e.response.text}')
    except requests.exceptions.RequestException as e:
        logger.error(f'Request error: {e}')


def main():
    args = parse_arguments()
    
    path = f'/v2/origin/custom/{args.id}/disconnect'
    url = f'https://amojo.amocrm.ru{path}'
    
    logger.debug(f'[+] URL: {url}')
    
    payload = json.dumps({'account_id': args.amojo})
    logger.debug(f'[+] Payload: {payload}')
    
    method = 'DELETE'
    check_sum, date, signature = create_signature(method, payload, path, args.secret)
    
    headers = {
        'Date': date,
        'Content-Type': 'application/json',
        'Content-MD5': check_sum,
        'X-Signature': signature
    }
    
    logger.debug(f'Headers: {headers}')
    
    logger.info('Trying to request...')
    response = make_request(url, headers, payload)
    
    if response:
        logger.success(f'Success: {response.status_code}')


if __name__ == "__main__":
    main()
