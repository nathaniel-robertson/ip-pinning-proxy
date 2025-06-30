# IP Pinning Proxy Tool

This is a web-based proxy tool built with Python and Flask that allows you to browse a website while forcing all of its requests to be "pinned" to a specific IP address. This is useful for testing changes on a specific server behind a load balancer or CDN before DNS has propagated, or for other development and testing scenarios.

The application rewrites all HTML, CSS, and JavaScript on the fly to ensure that links, images, and other resources are correctly routed through the proxy, providing a seamless browsing experience.

## Features

- **IP Pinning**: Bypasses DNS lookups for the target domain and routes all traffic to a specified IP address.
- **SNI Support**: Correctly handles modern, secure websites hosted on shared IPs (e.g., behind Cloudflare) by sending the appropriate Server Name Indication.
- **Comprehensive Content Rewriting**:
    - Rewrites `href`, `src`, and `srcset` attributes in HTML to keep navigation within the proxy.
    - Rewrites `url()` paths found in inline `style` attributes.
    - Replaces instances of the domain name in visible text content.
- **Dynamic Content Handling (Experimental)**: Optionally injects a `MutationObserver` script to rewrite links and resources that are added to the page dynamically by JavaScript.
- **Secure Authentication**:
    - Protects the entire tool with Basic Authentication.
    - Supports both plaintext passwords for simplicity and secure `bcrypt` hashed passwords for enhanced security.
- **User-Friendly UI**: A simple homepage allows you to easily input a target domain/URL and IP address, with helper features like automatic DNS lookup.
- **Configurable via Environment Variables**: All configuration (credentials, logging) is handled through environment variables for easy deployment.
- **Verbose Logging**: Optional detailed logging for easier debugging.

---

## Project Structure

The repository is structured as a standard Flask application.


```
/ 
├── app.py              # The main Flask application logic
├── templates/` 
│   └── index.html      # The HTML for the front-page UI
├── requirements.txt    # Lists the Python libraries needed
├── Procfile            # Tells the hosting service how to run the app
└── hash_password.py    # A utility script for generating secure password hashes
```

**Note:** `hash_password.py` is a developer utility and is not part of the running web application. It will not be accessible via the web.

---

## Deployment

This application is designed for easy deployment to a platform-as-a-service (PaaS) like Kinsta Application Hosting, Heroku, or Render.

**Step 1: Push to a Git Repository**
Create a new repository on a service like GitHub and push all the project files to it.

**Step 2: Create a New Application**
On your hosting platform, create a new application and connect it to your Git repository.

**Step 3: Configure Environment Variables**
In your application's settings, you must set the following environment variables to configure the proxy's authentication:

- **`PROXY_USER`**: The username for Basic Auth.
- **`PROXY_PASSWORD`**: The password for Basic Auth. This can be a plaintext password or a secure bcrypt hash (see Security section below).

You can also set these optional variables:

- **`PROXY_VERBOSE_LOGGING`**: Set to `true` to enable detailed request logging.
- **`PYTHON_VERSION`**: Set to a recent version, e.g., `3.12.1`.

**Step 4: Configure the Start Command**
Your hosting platform will likely detect the `Procfile` automatically. If you need to set the start command manually, use:
`gunicorn app:app`

The platform will then build the application by installing the dependencies from `requirements.txt` and start the web server.

---

## Usage

1.  Navigate to the homepage of your deployed application.
2.  Enter the username and password you configured in the environment variables.
3.  In the "Domain Name or Full URL" field, enter the website you wish to browse (e.g., `https://example.com/some/page`). The tool will automatically parse the domain and path.
4.  The "Pin to IP Address" field will auto-populate with the domain's current IP. You can override this with any IP address you want to target.
5.  Select your desired options for the User-Agent and dynamic content rewriting. These preferences will be saved in a cookie.
6.  Click "Start Browsing".

---

## Security: Using Hashed Passwords

For enhanced security, it is highly recommended to use a hashed password instead of a plaintext one. This prevents your actual password from being exposed if your environment variables are ever leaked.

The application automatically detects if the `PROXY_PASSWORD` is a hash (if it starts with `$2b$`) and uses the appropriate secure verification method.

**How to Generate a Hash:**

1.  On your **local machine**, ensure you have `bcrypt` installed (`pip install bcrypt`).
2.  Run the utility script from your terminal: `python hash_password.py`
3.  Enter and confirm your desired password when prompted.
4.  The script will output a long hash string.
5.  Copy this entire hash string.
6.  In your hosting platform's settings, paste the hash as the value for the `PROXY_PASSWORD` environment variable.

---

## Local Development

To run the tool on your local machine for testing or development:

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <repo-directory>
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **(Optional) Set environment variables:**
    For Linux/macOS:
    ```bash
    export PROXY_USER=admin
    export PROXY_PASSWORD=secret
    export PROXY_VERBOSE_LOGGING=true
    ```
    For Windows (Command Prompt):
    ```bash
    set PROXY_USER=admin
    set PROXY_PASSWORD=secret
    set PROXY_VERBOSE_LOGGING=true
    ```
5.  **Run the application:**
    ```bash
    python app.py
    ```
6.  Open your browser and navigate to `http://127.0.0.1:8080`.