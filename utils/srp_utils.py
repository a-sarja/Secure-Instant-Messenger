import srp
import config.config


def create_srp_user(username, password):
    return srp.User(username=username, password=password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)


def create_srp_salt_vkey(user_name, password):

    if not user_name or not password:
        print('Username and/or password cannot be empty!')
        return

    # Read password for the username from config (or database for more security)
    # Create SRP params like salt and verification key
    srp_salt, srp_vkey = srp.create_salted_verification_key(username=user_name, password=password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    if srp_salt and srp_vkey:
        return srp_salt, srp_vkey


def get_srp_salt_vkey(user_name):

    if not user_name:
        print('Username cannot be empty!')
        return

    srp_salt = config.config.secure_storage[user_name][0]
    srp_vkey = config.config.secure_storage[user_name][1]
    if srp_salt and srp_vkey:
        return srp_salt, srp_vkey


def srp_verifier(uname, srp_salt, srp_v_key, A):

    return srp.Verifier(username=uname, bytes_s=srp_salt, bytes_v=srp_v_key, bytes_A=A, hash_alg=srp.SHA256, ng_type=srp.NG_2048)

