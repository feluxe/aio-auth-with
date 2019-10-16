import aiohttp
from auth_with import github
from sanic import Blueprint, response

bp = Blueprint('oauth')


@bp.get('/github/login')
async def github_login(req):
    """
    Send user to github login form.
    """
    cfg = req.app.config

    url = github.generate_auth_endpoint(
        client_id=cfg.get('GITHUB_ID'),
        scope="user:email",
    )

    return response.redirect(to=url)


@bp.get('/github/callback')
async def github_auth_callback(req):
    """
    The user is send here after s/he accepts github authentication.
    """

    # get temporary access code from URL params.
    combined_data = {**req.form, **req.args}
    session_code = combined_data.get('code')[0]
    cfg = req.app.config

    # Send credentials to github API.
    access_token = await github.get_access_token(
        session_code=session_code,
        client_id=cfg.get('GITHUB_ID'),
        client_secret=cfg.get('GITHUB_PASSWORD'),
    )

    # Depending on the value set in 'scope', you can now access user's data.

    headers = {
        'content-type': 'application/json',
        'Accept': 'application/json',
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(
            'https://api.github.com/user',
            params={'access_token': access_token},
            headers=headers,
        ) as result:
            data = await result.json()
            print('USER DATA', data)

    async with aiohttp.ClientSession() as session:
        async with session.get(
            'https://api.github.com/user/emails',
            params={'access_token': access_token},
            headers=headers,
        ) as result:
            data = await result.json()
            print('USER EMAIL', data)

    return response.text(combined_data)
