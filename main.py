''' this project have the ability to check if our pass word have ever been found or tempered by someone else'''

import requests
import hashlib
import sys


'''Inorder to protect and secure our password 'magira22@jnuimi', we need to used the SHAI1 version of our 
password in the SHAI1 website and we are going to use only the first 5 values of our SHAI1 password the
api.pwnedpasswords allows us to trust no one as it will completely protect our password and we can send
a message to someone without knowing who we are
'''


def request_api_data(query_char):  # this function is going to check our data and give us an responds'''

    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching:{res.status_code}, please check the api and try again')
    return res


def get_password_leaks_count(hashes,hash_to_check):  # this function will print out all the response that matched with my
    # SHAI1 password
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
    # print(h, count)


def pwned_api_check(password):
    shai1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = shai1password[:5], shai1password[5:]  # [:5] will grape the first five characters
    # of our SHAI1 password characters and [5:] will grape the remaining SHAI1 password characters
    response = request_api_data(first5_char)
    # print(response)
    return get_password_leaks_count(response, tail)


def main(args):  # this will accept any arguments we gave as our password
    for password in args:
        count = pwned_api_check(password)  # this will count and check the passwords we gave from the Pwned_api_check password
        if count:  # this means if count exist then print the below statements
            print(f'{password} was found {count} times....you should probably change your password')
        else:  # this means if password don't exist then print the below statement
            print(f'{password} was not found. Carry on')
    return 'done!'


if __name__ == '__main__':  # this means that the code is going to work if the main only the final file is been run
    sys.exit(main(sys.argv[1:]))  # this will accept any number of argument or passwords we want to check. [sys.exit]
    # will exit the program and return us back to the command line

