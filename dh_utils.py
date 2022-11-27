
def calculate_dh_component(g, p, power):

    if not isinstance(power, int):
        power = int(''.join(format(ord(i), '08b') for i in power))

    return pow(g, power, p)


def calculate_key(a, partner_component, g, p, u, w):
    # a: `my_component`
    # partner_component : `g^b + g^w mod p`
    # g and p: DH components (public)
    # u: unique 32 bits number sent by server
    # w: client password

    password_component = calculate_dh_component(g, p, w)    # g^W MOD p
    g_power_b = partner_component - password_component      # (g^b + g^W MOD p) - password_component = g^b

    g_power_ab = pow(g_power_b, a)      # g ^ab
    g_power_buw = pow(g_power_b, (u*w))

    return (g_power_ab * g_power_buw) % p


if __name__ == '__main__':

    try:
        password = ''
        res = ''.join(format(ord(i), '08b') for i in password)

        print(calculate_dh_component(g=9, p=23, power=int(res)))

    except Exception as ex:
        print('Some exception : ' + str(ex))
