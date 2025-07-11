# app.py
import os
import socket
import re
import logging
import bcrypt # NEW: Import bcrypt
from functools import wraps
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, url_for)

# --- (SNI-Fix is unchanged) ---
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

# --- (Application Setup & Logging are unchanged) ---
app = Flask(__name__)
if os.environ.get('PROXY_VERBOSE_LOGGING'):
    app.logger.setLevel(logging.DEBUG)
    app.logger.info("Verbose logging enabled.")
else:
    app.logger.setLevel(logging.WARNING)

# --- MODIFIED: Smart Authentication Logic ---
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        proxy_user = os.environ.get("PROXY_USER")
        proxy_password = os.environ.get("PROXY_PASSWORD")
        # If no credentials are set, allow access (for easy local dev)
        if not proxy_user or not proxy_password:
            return f(*args, **kwargs)

        auth = request.authorization
        # Check if login credentials were provided by the browser
        if not auth or not auth.username or not auth.password:
            return Response(
                'Could not verify your access level.', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )

        # Check for username match first
        if auth.username != proxy_user:
            return Response('Invalid username.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

        # Smart password check
        is_password_correct = False
        stored_credential = os.environ.get("PROXY_PASSWORD", "")
        provided_password = auth.password.encode('utf-8')

        if stored_credential.startswith('$2b$'):
            # If it looks like a hash, use bcrypt to check
            app.logger.debug("Verifying password against a bcrypt hash.")
            is_password_correct = bcrypt.checkpw(provided_password, stored_credential.encode('utf-8'))
        else:
            # Otherwise, use simple plaintext comparison
            app.logger.debug("Verifying password against plaintext string.")
            is_password_correct = (auth.password == stored_credential)

        if not is_password_correct:
            return Response('Invalid password.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        
        # If we get here, authentication succeeded
        return f(*args, **kwargs)
    return decorated

# --- (All other routes and logic are unchanged) ---
@app.route('/')
@auth_required
def index():
    return render_template('index.html')

# ... (rest of the file is identical to the previous version) ...
@app.route('/dns-lookup')
@auth_required
def dns_lookup():
    domain = request.args.get('domain');
    if not domain: return jsonify({"error": "Domain parameter is required"}), 400
    try: ip_address = socket.gethostbyname(domain); return jsonify({"ip": ip_address})
    except socket.gaierror: return jsonify({"error": "Domain not found"}), 404

@app.route('/<string:target_ip>/<string:target_domain>/', defaults={'path': ''})
@app.route('/<string:target_ip>/<string:target_domain>/<path:path>')
@auth_required
def proxy_request(target_ip, target_domain, path):
    app.logger.info(f"Request for {target_domain} (pinned to {target_ip}) at path /{path} from client {request.remote_addr}")
    session = requests.Session(); session.mount(f"https://{target_domain}", HostPinningAdapter())
    if request.query_string: path = f"{path}?{request.query_string.decode('utf-8')}"
    url_to_fetch = f"https://{target_domain}/{path}"
    headers = { 'User-Agent': request.headers.get('User-Agent'), 'X-Forwarded-For': request.remote_addr, 'Accept-Encoding': 'gzip, deflate' }
    if request.cookies.get('addUaSuffix') == 'true':
        headers['User-Agent'] += " Nat's IP Pinning Proxy Tool"
        app.logger.debug("Appending custom string to User-Agent.")
    try:
        proxied_response = session.get( url_to_fetch, headers=headers, allow_redirects=False, stream=True )
        app.logger.debug(f"Upstream response: {proxied_response.status_code} | {proxied_response.headers.get('Content-Type', 'N/A')}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Upstream connection error: {e}")
        return f"<h1>Proxy Error</h1><p>Could not connect to IP {target_ip} for domain {target_domain}.</p><p>{e}</p>", 502
    if proxied_response.is_redirect:
        location = proxied_response.headers['location']; parsed_loc = urlparse(location)
        if parsed_loc.netloc == target_domain:
            new_path = f"/{target_ip}/{target_domain}{parsed_loc.path}" + (f"?{parsed_loc.query}" if parsed_loc.query else "")
            return redirect(new_path)
        elif not parsed_loc.netloc:
             return redirect(f"/{target_ip}/{target_domain}/{location.lstrip('/')}")
        else: return redirect(location)
    content_type = proxied_response.headers.get('Content-Type', '').lower()
    if 'text/html' in content_type:
        app.logger.debug("Performing static HTML rewrite.")
        soup = BeautifulSoup(proxied_response.content, 'html.parser')
        proxy_root_path = f"/{target_ip}/{target_domain}"
        def rewrite_url(url_string):
            if (not url_string or url_string.startswith(('#', 'data:', 'mailto:', 'tel:'))): return url_string
            parsed_url = urlparse(url_string)
            if parsed_url.netloc == target_domain: return f"{proxy_root_path}{parsed_url.path}" + (f"?{parsed_url.query}" if parsed_url.query else "")
            elif not parsed_url.scheme and not parsed_url.netloc:
                base_path = os.path.dirname(path.split('?')[0]); absolute_path = os.path.normpath(os.path.join(base_path, url_string))
                return f"{proxy_root_path}{absolute_path}"
            return url_string
        for tag in soup.find_all(attrs={'href': True}): tag['href'] = rewrite_url(tag['href'])
        for tag in soup.find_all(attrs={'src': True}): tag['src'] = rewrite_url(tag['src'])
        for tag in soup.find_all(attrs={'srcset': True}):
            rewritten_parts = [];
            for part in tag['srcset'].split(','):
                part = part.strip();
                if not part: continue
                match = re.match(r'(\S+)(\s+.*)?', part);
                if match: url, descriptor = match.groups(); rewritten_parts.append(rewrite_url(url) + (descriptor or ""))
            tag['srcset'] = ', '.join(rewritten_parts)
        url_pattern = re.compile(r'url\s*\((?!["\']?data:)["\']?([^"\'\)]*)["\']?\s*\)', re.IGNORECASE)
        for tag in soup.find_all(attrs={'style': True}):
            tag['style'] = re.sub(url_pattern, lambda m: f"url({rewrite_url(m.group(1))})", tag['style'])
        if soup.body:
            text_pattern = re.compile(r'(?<!@)\b' + re.escape(target_domain) + r'\b', re.IGNORECASE)
            for node in soup.body.find_all(string=True):
                if node.parent.name in ['script', 'style'] or isinstance(node, Comment): continue
                node.replace_with(text_pattern.sub(proxy_root_path, node))
        if request.cookies.get('dynamicRewrite') == 'true' and soup.head:
            app.logger.debug("Injecting dynamic MutationObserver script.")
            observer_script_text = f'''...''' # (omitted for brevity)
            script_tag = soup.new_tag("script"); script_tag.string = observer_script_text; soup.head.append(script_tag)
        content = soup.prettify()
    else:
        content = proxied_response.raw
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers_to_pass = [(k, v) for k, v in proxied_response.raw.headers.items() if k.lower() not in excluded_headers]
    app.logger.info(f"Responding to client with status {proxied_response.status_code}.")
    return Response(content, proxied_response.status_code, headers_to_pass)

if __name__ == '__main__':
    app.run(debug=True, port=8080)