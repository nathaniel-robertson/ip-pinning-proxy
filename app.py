# app.py
import os
import socket
from functools import wraps
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, url_for)

# --- NEW: Custom Adapter for IP Pinning ---
# This is the core of the more robust solution. It allows us to control
# the destination IP address for a request without changing the URL.

# 1. Create a custom DNS resolver.
#    Instead of looking up a host, it will always return our pinned IP.
_original_getaddrinfo = socket.getaddrinfo

def getaddrinfo_pinned(host, port, family=0, type=0, proto=0, flags=0):
    """A custom DNS resolver that returns a pinned IP for a specific host."""
    # The host we want to pin is passed via a thread-local variable,
    # but for simplicity in this example, we retrieve it from the request context.
    # A more complex app might use threading.local()
    pinned_host = request.view_args['target_domain']
    pinned_ip = request.view_args['target_ip']
    
    if host == pinned_host:
        # If the host matches, ignore DNS and return the pinned IP.
        # This tricks `requests` into connecting to our desired IP.
        return _original_getaddrinfo(pinned_ip, port, family, type, proto, flags)
    
    # For any other host (e.g., during a redirect), use the real DNS.
    return _original_getaddrinfo(host, port, family, type, proto, flags)


# 2. Create a custom HTTPAdapter that uses our DNS patch.
class HostPinningAdapter(requests.adapters.HTTPAdapter):
    """An HTTP adapter that pins a hostname to a specific IP address."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        # When a request is sent through this adapter, temporarily
        # patch the system's DNS resolver with our custom one.
        socket.getaddrinfo = getaddrinfo_pinned
        try:
            # Call the original send method, which will now use our pinned IP
            return super().send(request, **kwargs)
        finally:
            # Always restore the original resolver.
            socket.getaddrinfo = _original_getaddrinfo


# --- Application Setup ---
app = Flask(__name__)

# --- Authentication ---
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        proxy_user = os.environ.get("PROXY_USER")
        proxy_password = os.environ.get("PROXY_PASSWORD")
        if not proxy_user or not proxy_password:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not (auth.username == proxy_user and auth.password == proxy_password):
            return Response(
                'Could not verify your access level.', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
@auth_required
def index():
    return render_template('index.html')

@app.route('/dns-lookup')
@auth_required
def dns_lookup():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400
    try:
        ip_address = socket.gethostbyname(domain)
        return jsonify({"ip": ip_address})
    except socket.gaierror:
        return jsonify({"error": "Domain not found"}), 404

@app.route('/<string:target_domain>/<string:target_ip>/', defaults={'path': ''})
@app.route('/<string:target_domain>/<string:target_ip>/<path:path>')
@auth_required
def proxy_request(target_domain, target_ip, path):
    
    # --- MODIFIED: Use the new SNI-compatible approach ---
    
    # Create a requests Session object.
    session = requests.Session()
    
    # Mount our custom adapter to the session. This tells the session:
    # "For any request to `https://{target_domain}`, use our HostPinningAdapter."
    session.mount(f"https://{target_domain}", HostPinningAdapter())

    # The URL we fetch is now the *correct* URL with the domain name.
    # Our adapter will ensure it connects to `target_ip` under the hood.
    if request.query_string:
        path = f"{path}?{request.query_string.decode('utf-8')}"
    url_to_fetch = f"https://{target_domain}/{path}"

    headers = {
        'User-Agent': request.headers.get('User-Agent'),
        # The 'Host' header is now set correctly by default by `requests`
        # because we are connecting to a proper domain name.
        'X-Forwarded-For': request.remote_addr,
        'Accept-Encoding': 'gzip, deflate',
    }
    
    if request.args.get('add_ua_suffix') == 'true':
        headers['User-Agent'] += " Nat's IP Pinning Proxy Tool"

    try:
        # Use the session object to make the request.
        # We can now REMOVE `verify=False`. Because we send the correct SNI,
        # the server returns the correct certificate, and validation will pass.
        proxied_response = session.get(
            url_to_fetch,
            headers=headers,
            allow_redirects=False,
            stream=True
        )
    except requests.exceptions.SSLError as e:
        return f"<h1>Proxy SSL Error</h1><p>An SSL error occurred, even with SNI fix. The server might be using a self-signed or invalid certificate.</p><p>{e}</p>", 502
    except requests.exceptions.RequestException as e:
        return f"<h1>Proxy Error</h1><p>Could not connect to IP {target_ip} for domain {target_domain}.</p><p>{e}</p>", 502

    # --- (The rest of the code for handling redirects and rewriting content is identical) ---

    if proxied_response.is_redirect:
        location = proxied_response.headers['location']
        parsed_loc = urlparse(location)
        if parsed_loc.netloc == target_domain:
            new_path = f"/{target_domain}/{target_ip}{parsed_loc.path}"
            if parsed_loc.query:
                new_path += f"?{parsed_loc.query}"
            return redirect(new_path)
        elif not parsed_loc.netloc:
             return redirect(f"/{target_domain}/{target_ip}/{location.lstrip('/')}")
        else:
            return redirect(location)

    content_type = proxied_response.headers.get('Content-Type', '').lower()
    if 'text/html' in content_type:
        soup = BeautifulSoup(proxied_response.content, 'html.parser')
        for tag in soup.find_all(attrs={'href': True}) + soup.find_all(attrs={'src': True}):
            attr = 'href' if 'href' in tag.attrs else 'src'
            url = tag[attr]
            if not url or url.startswith('#') or url.startswith('data:'):
                continue
            parsed_url = urlparse(url)
            if parsed_url.netloc == target_domain:
                tag[attr] = f"/{target_domain}/{target_ip}{parsed_url.path}"
                if parsed_url.query:
                    tag[attr] += f"?{parsed_url.query}"
            elif not parsed_url.scheme and not parsed_url.netloc:
                base_path = os.path.dirname(path.split('?')[0])
                absolute_path = os.path.normpath(os.path.join(base_path, url))
                tag[attr] = f"/{target_domain}/{target_ip}{absolute_path}"
        content = soup.prettify()
    else:
        content = proxied_response.raw

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers_to_pass = [
        (k, v) for k, v in proxied_response.raw.headers.items() if k.lower() not in excluded_headers
    ]
    return Response(content, proxied_response.status_code, headers_to_pass)


if __name__ == '__main__':
    app.run(debug=True, port=8080)