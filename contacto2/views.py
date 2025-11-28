from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
import json

from . import api_client


def login_view(request):
    """Autentica contra la API externa y guarda el token en sesión."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        auth = api_client.login_to_external_api(username, password)
        if auth:
            # Guardar token o cookies según el esquema detectado
            scheme = auth.get('scheme')
            request.session['external_api_scheme'] = scheme or 'Token'
            # Guardar también el nombre de usuario externo para mostrar en la UI
            request.session['external_api_user'] = username
            if scheme == 'Session':
                request.session['external_api_session'] = auth.get('cookies')
            else:
                request.session['external_api_token'] = auth.get('token')
            return redirect('obtener_productos')
        else:
            messages.error(request, 'Credenciales inválidas para la API externa')

    return render(request, 'contactos/login.html')


def obtener_productos(request):
    """Obtiene contactos desde la API externa usando el token guardado en sesión."""
    token = request.session.get('external_api_token')
    scheme = request.session.get('external_api_scheme', 'Token')
    cookies = request.session.get('external_api_session')

    # Si no hay credenciales en sesión, pedir login
    if not token and scheme != 'Session' and not cookies:
        messages.info(request, 'Debes iniciar sesión para ver los contactos')
        return redirect('login')

    productos = api_client.get_contacts_from_api(token=token, scheme=scheme, cookies=cookies)

    # Si la API devuelve un objeto paginado {'count':.., 'results':[...]} tomar 'results'
    if isinstance(productos, dict) and 'results' in productos:
        productos = productos.get('results') or []

    context = {
        'productos': productos,
        'productos_json': json.dumps(productos, ensure_ascii=False, indent=2),
        'user': request.user if request.user.is_authenticated else None,
    }
    return render(request, 'contactos/contactos.html', context)