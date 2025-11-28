import requests
import logging
from django.conf import settings

log = logging.getLogger(__name__)


def login_to_external_api(username, password, timeout=5):
    """Intenta autenticarse en la API externa.

    Flujo:
    1) Intentar autenticación tipo token/JSON (ej. devuelve {'token':...} o {'access':...}).
    2) Si no hay token, intentar autenticación por sesión (form login) y devolver las cookies.

    Devuelve un dict con una de las formas:
      - {'token': '<val>', 'scheme': 'Token'|'Bearer'}
      - {'cookies': {..}, 'scheme': 'Session'}
      - None si falla
    """
    auth_url = getattr(settings, 'CONTACTOS_AUTH_URL', None)
    if not auth_url:
        return None

    # 1) Probar endpoint JSON/token
    try:
        resp = requests.post(auth_url, data={'username': username, 'password': password}, timeout=timeout)
        # No levantar excepción todavía; algunos endpoints devuelven 400/401 para credenciales malas
        try:
            data = resp.json()
        except ValueError:
            data = None

        # log para depuración
        log.info('Auth JSON attempt: url=%s status=%s', auth_url, getattr(resp, 'status_code', None))
        log.debug('Auth JSON response body: %s', getattr(resp, 'text', '')[:1000])

        if isinstance(data, dict):
            token = data.get('token') or data.get('access') or data.get('key')
            if token:
                scheme = 'Bearer' if 'access' in data else 'Token'
                log.info('Detected token auth: scheme=%s', scheme)
                return {'token': token, 'scheme': scheme}
    except requests.RequestException:
        # continuamos al intento por sesión
        pass

    # 2) Intentar login por sesión (form-based) y devolver cookies si funcionan.
    # Muchas vistas de login Django requieren CSRF, así que primero hacemos GET
    # para obtener la cookie `csrftoken` y luego POST con ese token.
    try:
        sess = requests.Session()
        get_resp = sess.get(auth_url, timeout=timeout)
        # intentar obtener csrf token de cookies
        csrftoken = sess.cookies.get('csrftoken') or sess.cookies.get('csrf')
        # si no está en cookies, intentar extraer del HTML (campo hidden)
        if not csrftoken and get_resp is not None and get_resp.text:
            import re
            m = re.search(r"name=['\"]csrfmiddlewaretoken['\"] value=['\"]([0-9a-zA-Z]+)['\"]", get_resp.text)
            if m:
                csrftoken = m.group(1)

        post_headers = {'Referer': auth_url}
        post_data = {'username': username, 'password': password}
        if csrftoken:
            post_data['csrfmiddlewaretoken'] = csrftoken
            post_headers['X-CSRFToken'] = csrftoken

        post_resp = sess.post(auth_url, data=post_data, headers=post_headers, timeout=timeout, allow_redirects=True)

        # log para depuración
        log.info('Auth session attempt: url=%s status=%s', auth_url, getattr(post_resp, 'status_code', None))
        log.debug('Auth session response headers: %s', getattr(post_resp, 'headers', {}))
        log.debug('Auth session response body: %s', getattr(post_resp, 'text', '')[:2000])

        cookies = sess.cookies.get_dict()
        log.info('Auth session cookies: %s', cookies)

        # si obtuvimos sessionid u otra cookie de sesión, consideramos login OK
        if cookies and ('sessionid' in cookies or 'csrftoken' in cookies or len(cookies) > 0):
            return {'cookies': cookies, 'scheme': 'Session'}
    except requests.RequestException as e:
        log.exception('Session auth request failed: %s', e)
        return None

    return None


def get_contacts_from_api(token=None, scheme='Token', cookies=None, timeout=5):
    """Obtiene la lista de contactos desde la API externa.

    - Si `scheme` es 'Session' y `cookies` es dict, se enviarán como cookies en la petición.
    - Si `token` está presente se usará en el header `Authorization`.
    """
    api_url = getattr(settings, 'CONTACTOS_API_URL', None)
    if not api_url:
        return []

    headers = {}
    params = {}
    if scheme == 'Session' and cookies:
        params['cookies'] = cookies
    elif token:
        headers['Authorization'] = f'{scheme} {token}'

    try:
        resp = requests.get(api_url, headers=headers, timeout=timeout, **params)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        return []

    return []
