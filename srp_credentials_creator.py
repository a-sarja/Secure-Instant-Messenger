import argparse
import srp


def create_srp_salt_vkey(user_name, password):

    if not user_name or not password:
        print('Username and/or password cannot be empty!')
        return

    # Read password for the username from config (or database for more security)
    # Create SRP params like salt and verification key
    srp_salt, srp_vkey = srp.create_salted_verification_key(username=user_name, password=password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    if srp_salt and srp_vkey:
        return srp_salt, srp_vkey


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", type=str, required=True, help="Username is required. It is the unique name.")
    parser.add_argument("-p", "--password", type=str, required=True, help="Password is required")

    args = parser.parse_args()
    username = args.username
    password = args.password

    # salt, vkey = create_srp_salt_vkey(user_name=username, pass_word=password)
    salt, vkey = create_srp_salt_vkey(user_name=username, password=password)

    print(salt)
    print('\n\n')
    print(vkey)
