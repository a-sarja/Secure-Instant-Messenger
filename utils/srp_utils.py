import argparse

import srp

import config.config


def create_srp_salt_vkey(user_name):

    if not user_name:
        print('Username cannot be empty!')
        return

    # Read password for the username from config (or database for more security)
    pass_word = config.config.secure_storage[user_name]

    # Create SRP params like salt and verification key
    srp_salt, srp_vkey = srp.create_salted_verification_key(user_name, pass_word)
    if srp_salt and srp_vkey:
        return srp_salt, srp_vkey


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", type=str, required=True, help="Username is required. It is the unique name.")
    # parser.add_argument("-p", "--password", type=str, required=True, help="Password is required")

    args = parser.parse_args()
    username = args.username
    # password = args.password

    # salt, vkey = create_srp_salt_vkey(user_name=username, pass_word=password)
    salt, vkey = create_srp_salt_vkey(user_name=username)
    print(salt)
    print('\n')
    print(vkey)
