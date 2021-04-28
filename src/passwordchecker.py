import requests
import hashlib
import sys

def request_api_data(password):
    url = 'https://api.pwnedpasswords.com/range/' + password
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again!')
    return res

def pwned_api_check(fullpassword):
    sha1password = hashlib.sha1(fullpassword.encode('utf-8')).hexdigest().upper()
    password_reduced, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(password_reduced)
    return get_password_leaks(response, tail)

def get_password_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times... you should probably change your password!")
        else:
            print(f"{password} was not found! Good password!")
    return 'Done!'

main(sys.argv[1:])