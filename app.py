# app.py
import os
import socket
import re
from functools import wraps
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, url_for)

# --- (SNI-Fix: Custom Adapter, getaddrinfo_pinned, and HostPinningAdapter class are unchanged) ---
_original_getaddrinfo = socket.getaddrinfo

def getaddrinfo_pinned(host, port, family=0, type=0, proto=0, flags=0):
    pinned_host = request.view_args['target_domain']
    pinned_ip = request.view_args['target_ip']
    if host == pinned_host:
        return _original_getaddrinfo(pinned_ip, port, family, type, proto, flags)
    return _original_getaddrinfo(host, port, family, type, proto, flags)

class HostPinningAdapter(requests.adapters.HTTPAdapter):
    def send(self, request, **kwargs):
        socket.getaddrinfo = getaddrinfo_pinned
        try:
            return super().send(request, **kwargs)
        finally:
            socket.getaddrinfo = _original_getaddrinfo

# --- Application Setup & Auth (unchanged) ---
app = Flask(__name__)

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

# --- Routes (index, dns_lookup are unchanged) ---
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

# --- Proxy Route (Main logic updated) ---
@app.route('/<string:target_domain>/<string:target_ip>/', defaults={'path': ''})
@app.route('/<string:target_domain>/<string:target_ip>/<path:path>')
@auth_required
def proxy_request(target_domain, target_ip, path):
    
    # --- (SNI-Fix Session and request sending logic is unchanged) ---
    session = requests.Session()
    session.mount(f"https://{target_domain}", HostPinningAdapter())
    if request.query_string:
        path = f"{path}?{request.query_string.decode('utf-8')}"
    url_to_fetch = f"https://{target_domain}/{path}"
    headers = { 'User-Agent': request.headers.get('User-Agent'), 'X-Forwarded-For': request.remote_addr, 'Accept-Encoding': 'gzip, deflate' }
    if request.args.get('add_ua_suffix') == 'true':
        headers['User-Agent'] += " Nat's IP Pinning Proxy Tool"

    try:
        proxied_response = session.get( url_to_fetch, headers=headers, allow_redirects=False, stream=True )
    except requests.exceptions.SSLError as e:
        return f"<h1>Proxy SSL Error</h1><p>An SSL error occurred, even with SNI fix. The server might be using a self-signed or invalid certificate.</p><p>{e}</p>", 502
    except requests.exceptions.RequestException as e:
        return f"<h1>Proxy Error</h1><p>Could not connect to IP {target_ip} for domain {target_domain}.</p><p>{e}</p>", 502

    # --- (Redirect handling logic is unchanged) ---
    if proxied_response.is_redirect:
        location = proxied_response.headers['location']
        parsed_loc = urlparse(location)
        if parsed_loc.netloc == target_domain:
            new_path = f"/{target_domain}/{target_ip}{parsed_loc.path}" + (f"?{parsed_loc.query}" if parsed_loc.query else "")
            return redirect(new_path)
        elif not parsed_loc.netloc:
             return redirect(f"/{target_domain}/{target_ip}/{location.lstrip('/')}")
        else:
            return redirect(location)

    content_type = proxied_response.headers.get('Content-Type', '').lower()
    
    # --- MODIFIED: Expanded Content Rewriting Logic ---
    if 'text/html' in content_type:
        soup = BeautifulSoup(proxied_response.content, 'html.parser')
        
        proxy_root_path = f"/{target_domain}/{target_ip}"

        def rewrite_url(url_string):
            # FIX 1: Ignore common non-HTTP URI schemes like mailto: and tel:
            if (not url_string or url_string.startswith('#') or 
                url_string.startswith('data:') or url_string.startswith('mailto:') or
                url_string.startswith('tel:')):
                return url_string
            
            parsed_url = urlparse(url_string)
            if parsed_url.netloc == target_domain:
                return f"{proxy_root_path}{parsed_url.path}" + (f"?{parsed_url.query}" if parsed_url.query else "")
            elif not parsed_url.scheme and not parsed_url.netloc:
                base_path = os.path.dirname(path.split('?')[0])
                absolute_path = os.path.normpath(os.path.join(base_path, url_string))
                return f"{proxy_root_path}{absolute_path}"
            return url_string

        # 1. Rewrite standard attributes
        for tag in soup.find_all(attrs={'href': True}):
            tag['href'] = rewrite_url(tag['href'])
        for tag in soup.find_all(attrs={'src': True}):
            tag['src'] = rewrite_url(tag['src'])
        for tag in soup.find_all(attrs={'srcset': True}):
            rewritten_parts = []
            for part in tag['srcset'].split(','):
                part = part.strip()
                if not part: continue
                match = re.match(r'(\S+)(\s+.*)?', part)
                if match:
                    url, descriptor = match.groups()
                    rewritten_parts.append(rewrite_url(url) + (descriptor or ""))
            tag['srcset'] = ', '.join(rewritten_parts)

        # 2. Rewrite URLs within inline `style` attributes
        url_pattern = re.compile(r'url\s*\((?!["\']?data:)["\']?([^"\'\)]*)["\']?\s*\)', re.IGNORECASE)
        for tag in soup.find_all(attrs={'style': True}):
            new_style = re.sub(url_pattern, lambda m: f"url({rewrite_url(m.group(1))})", tag['style'])
            tag['style'] = new_style
            
        # 3. Search and replace domain in visible text content
        if soup.body:
            # FIX 2: Use a negative lookbehind `(?<!@)` to avoid matching domain names
            # that are part of an email address.
            text_pattern = re.compile(r'(?<!@)\b' + re.escape(target_domain) + r'\b', re.IGNORECASE)
            
            text_nodes = soup.body.find_all(string=True)
            for node in text_nodes:
                if node.parent.name in ['script', 'style'] or isinstance(node, Comment):
                    continue
                new_text = text_pattern.sub(proxy_root_path, node)
                node.replace_with(new_text)

        content = soup.prettify()
    else:
        content = proxied_response.raw

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers_to_pass = [(k, v) for k, v in proxied_response.raw.headers.items() if k.lower() not in excluded_headers]
    return Response(content, proxied_response.status_code, headers_to_pass)

if __name__ == '__main__':
    app.run(debug=True, port=8080)