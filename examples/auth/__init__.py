from os import urandom
import jwt
from sanic import response


def generate_auth_tokens(email, cfg) -> response:
    """
    An implementation of 'Double Submit Cookies Method':
        https://stackoverflow.com/a/37396572/1612318

    We generate two cookies. One is 'httponly' and contains the 'access token'.
    The other one is not 'httponly' and contains the 'csrf token'.

    We need these two cookies for user authentication.
    The access token is used to identify the user and store some user specific
    data. The csrf token is used to protect the user from csrf attacks.
    """
    access_token_key = cfg.ACCESS_TOKEN_KEY
    csrf_token_key = generate_key()

    access_token_encoded = jwt.encode(
        {'email': email, 'csrf_key': csrf_token_key},
        access_token_key,
        algorithm='HS256',
    )

    print('ENCODED ACCESS TOKEN', access_token_encoded)

    csrf_token_encoded = jwt.encode(
        {'email': email},
        csrf_token_key,
        algorithm='HS256',
    )

    print('ENCODED CSRF TOKEN', csrf_token_encoded)

    # Create Session Cookie that stores the jwt.
    res = response.redirect(to='/')
    res.cookies['access_token'] = access_token_encoded.decode('utf-8')
    res.cookies['access_token']['domain'] = cfg.COOKIE_DOMAIN
    res.cookies['access_token']['path'] = '/'
    res.cookies['access_token']['httponly'] = True
    res.cookies['access_token']['secure'] = cfg.PORTIER_WEBSITE_URL \
        .startswith('https://')

    # Create Session Cookie that stores the csrf token.
    res.cookies['csrf_token'] = csrf_token_encoded.decode('utf-8')
    res.cookies['csrf_token']['domain'] = cfg.COOKIE_DOMAIN
    res.cookies['csrf_token']['path'] = '/'
    res.cookies['csrf_token']['httponly'] = False
    res.cookies['csrf_token']['secure'] = cfg.PORTIER_WEBSITE_URL \
        .startswith('https://')

    return res


async def is_auth(req):
    """
    Check if a certain email address is logged-in.
    """
    email_cookie = req.cookies.get('email')
    #
    # if email_cookie:
    #     try:
    #         # unsigned_cookie = cookie_singer.unsign(
    #         #     value=email_cookie,
    #         #     max_age=1000
    #         # ).decode('utf-8')
    #         print('JWT ENCODED2', email_cookie)
    #
    #         jwt_decoded = jwt.decode(
    #             jwt=email_cookie,
    #             key=req.app.config.PORTIER_SECRET,
    #             algorithms='RS256',
    #         )
    #         print('DECODED JWT', jwt_decoded)
    #
    #         # if unsigned_cookie == 'felix@egoversum.com':
    #         #     return True
    #
    #     except BadTimeSignature:
    #         pass

    return False


def generate_key():
    """
    Create a random key for HS256 signer.
    """
    return bytearray(urandom(32)).hex()
