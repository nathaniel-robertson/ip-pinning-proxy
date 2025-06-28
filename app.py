# app.py
import os
import socket
from functools import wraps
from urllib.parse import urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, url_for)

# --- Application Setup ---
app = Flask(__name__)

# --- Authentication ---
# A simple decorator to protect routes with Basic Auth
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get credentials from environment variables
        proxy_user = os.environ.get("PROXY_USER")
        proxy_password = os.environ.get("PROXY_PASSWORD")

        # If no credentials are set in the environment, we allow access.
        # This is useful for local development. In production, always set them.
        if not proxy_user or not proxy_password:
            return f(*args, **kwargs)

        auth = request.authorization
        if not auth or not (auth.username == proxy_user and auth.password == proxy_password):
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
@auth_required
def index():
    """Renders the homepage UI."""
    return render_template('index.html')

@app.route('/dns-lookup')
@auth_required
def dns_lookup():
    """Performs a DNS lookup for the UI's autocomplete feature."""
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
    """The main proxy engine."""

    # Reconstruct the full path and query string
    if request.query_string:
        path = f"{path}?{request.query_string.decode('utf-8')}"
    
    # This is the key to IP pinning: we connect to the IP address directly
    # but use the 'Host' header to tell the server which domain we want.
    # We assume HTTPS for all modern websites.
    url_to_fetch = f"https://{target_ip}/{path}"

    headers = {
        # Pass through the user agent from the client
        'User-Agent': request.headers.get('User-Agent'),
        # This is CRUCIAL for the target server to know which website to serve
        'Host': target_domain,
        # Pass along the real client IP
        'X-Forwarded-For': request.remote_addr,
        'Accept-Encoding': 'gzip, deflate', # Allow requests to get compressed content
    }

    # Append custom string to User-Agent if the query parameter is set
    if request.args.get('add_ua_suffix') == 'true':
        headers['User-Agent'] += " Nat's IP Pinning Proxy Tool"
        
    try:
        # NOTE on verify=False:
        # When connecting via IP, the SSL certificate for `target_domain` will not match.
        # This causes an SSL verification error. For this specific tool, we must
        # disable verification. This is a calculated security risk; it means the
        # connection from YOUR PROXY to the target server is not verified.
        proxied_response = requests.get(
            url_to_fetch,
            headers=headers,
            allow_redirects=False, # We will handle redirects ourselves to keep them in the proxy
            stream=True, # Stream content to handle large files and improve performance
            verify=False
        )
    except requests.exceptions.RequestException as e:
        # If the server at the IP can't be reached
        return f"<h1>Proxy Error</h1><p>Could not connect to IP {target_ip}.</p><p>{e}</p>", 502

    # --- Handle Redirects ---
    if proxied_response.is_redirect:
        location = proxied_response.headers['location']
        # If the redirect is absolute, rewrite it to stay within the proxy
        parsed_loc = urlparse(location)
        if parsed_loc.netloc == target_domain:
            new_path = f"/{target_domain}/{target_ip}{parsed_loc.path}"
            if parsed_loc.query:
                new_path += f"?{parsed_loc.query}"
            return redirect(new_path)
        # If it's a relative redirect, handle it
        elif not parsed_loc.netloc:
             return redirect(f"/{target_domain}/{target_ip}/{location.lstrip('/')}")
        # If redirecting to a different domain, we can't proxy it, so send the user there directly
        else:
            return redirect(location)
            
    # --- Content Rewriting ---
    content_type = proxied_response.headers.get('Content-Type', '').lower()
    
    if 'text/html' in content_type:
        # Decode content and parse with BeautifulSoup
        soup = BeautifulSoup(proxied_response.content, 'html.parser')

        # Find all tags with 'href' or 'src' and rewrite their URLs
        for tag in soup.find_all(attrs={'href': True}) + soup.find_all(attrs={'src': True}):
            attr = 'href' if 'href' in tag.attrs else 'src'
            url = tag[attr]
            
            if not url or url.startswith('#') or url.startswith('data:'):
                continue
            
            parsed_url = urlparse(url)

            # If the URL is absolute and points to our target domain, rewrite it
            if parsed_url.netloc == target_domain:
                tag[attr] = f"/{target_domain}/{target_ip}{parsed_url.path}"
                if parsed_url.query:
                    tag[attr] += f"?{parsed_url.query}"
            # If the URL is relative (e.g., '/about' or 'style.css'), prepend the proxy path
            elif not parsed_url.scheme and not parsed_url.netloc:
                # Construct absolute path from relative path
                base_path = os.path.dirname(path.split('?')[0])
                absolute_path = os.path.normpath(os.path.join(base_path, url))
                tag[attr] = f"/{target_domain}/{target_ip}{absolute_path}"
        
        # Get the modified HTML
        content = soup.prettify()
    else:
        # For non-HTML content (images, CSS, JS), just stream it through
        content = proxied_response.raw

    # --- Return the Final Response ---
    # Create a new Flask response, copying status code and filtering headers.
    # We must remove 'Content-Encoding' as we've decoded it, and 'Content-Length'
    # as the length has changed. The web server will handle these.
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers_to_pass = [
        (k, v) for k, v in proxied_response.raw.headers.items() if k.lower() not in excluded_headers
    ]

    return Response(content, proxied_response.status_code, headers_to_pass)

# --- Main execution ---
if __name__ == '__main__':
    # For local development: run with debug mode on.
    # DO NOT use debug mode in production. Gunicorn will be used instead.
    app.run(debug=True, port=8080)