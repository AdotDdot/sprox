sprox
=====
Yet another http/https intercepting proxy featuring a console interface.

There are already several complete intercepting proxies written in Python, such as **mitmproxy**.
sprox is based on [sproxy](https://github.com/AdotDdot/sproxy), but features a console interface based on urwid.

Features
=======
  * Generate https certificates on the fly to allow https interception
  * Display requests and responses - you can display them either in basic mode, displaying only the first line of each request and response, or in full mode, displaying the full request and the head of the response.
  * Events log: displays error messages events relative to major socket events
  * Automatically decode url-encoded POST data
  
Getting it to work
==================
  * Make sure urwid is installed ([Installation instructions](https://github.com/wardi/urwid/wiki/Installation-instructions))
  * Run *setup.py*. It will create the needed directories and create the self-signed SSL certificate. You may specify the local certificates path (defaults to */etc/ssl/certs/ca-certificates.crt*) and the serial number of the self-signed certificate (defaults to 1).
  `python setup.py [localcert] [serial]`
  * In the newly-created directory *sproxy_files* you can find the certificate file *sproxy.pem*. Import it in your browser as a trusted certificate authority.
  * The proxy will run on port 50007. Configure your browser to use the proxy and run *sprox.py*
  
To do
=====
  * Allow user to run proxy on desired port
  * Allow user to intercept and modify requests on the fly
  * Allow user to blacklist hosts on the fly
  * Allow user to modify set timeouts on the fly
