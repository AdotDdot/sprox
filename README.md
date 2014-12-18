sprox
=====
Yet another http/https intercepting proxy featuring a console interface.
There are already several complete intercepting proxies written in Python, such as **mitmproxy**.

sprox is based on [sproxy](https://github.com/AdotDdot/sproxy), but features a console interface based on urwid.

Features
=======
  * Generate ssl certificates on the fly to allow https interception
  * Intercept and edit requests on the fly
  * Two output modes: display requests and responses either in basic mode (output the first line of each request and response) or in full mode (displaying the full request and the head of the response)
  * Display log of major socket events
  * Automatically decode url-encoded POST data
  
Screenshots
===========
Main screen, basic output mode
![screenshot1](http://i58.tinypic.com/246jb5l.png "Screenshot 1")

Main screen, full output mode
![screenshot2](http://i60.tinypic.com/339n08w.png "Screenshot 2")

Event log screen
![screenshot3](http://i58.tinypic.com/2v7vt51.png "Screenshot 3")

Request Editor
![screenshot4](http://i59.tinypic.com/2whigjl.png "Screenshot 4")

Getting it to work
==================
  * Make sure urwid is installed ([Installation instructions](https://github.com/wardi/urwid/wiki/Installation-instructions))
  * Run *setup.py*. It will create the needed directories and create the self-signed SSL certificate. You may specify the local certificates file path (defaults to */etc/ssl/certs/ca-certificates.crt*) and the serial number of the self-signed certificate (defaults to 1).
  `python setup.py [localcert] [serial]`
  * In the newly-created directory *sproxy_files* you can find the certificate file *sproxy.pem*. Import it in your browser as a trusted certificate authority.
  * Configure your browser to use the proxy and run *sprox.py*. You can specify the port in the command-line arguments (defaults to 50007).
  `python sprox.py [port]`

Intercepting requests
=====================
Type the desired interception pattern in the bottom bar and press ENTER to start intercepting.
Requests can be intercepted filtering methods, urls and headers content. The pattern to be set follows a command-line arguments syntax.
 * **-m** filter methods. Allowed arguments are g (GET), p (POST), d (DELETE), t (TRACE), u (PUT), o (OPTIONS), h (HEAD), c (CONNECT)
 * **-u** filter urls. The request will be intercepted if it contains all the -u arguments.
 * **-e** filter headers content. The syntax to follow is header-name=header-content. The request will be intercepted if the header indicated as header-name has as value header-content.

Examples:

    -m p
Intercept all POST requests.

    -m g -u github
Intercept GET requests whose url contains "github".

    -m g p -u github session -e connection=keep-alive
Intercept GET or POST requests whose url contains "github" and "session" and whose "Connection" header value is "Keep-alive".

After a request has been intercepted, its first line will be displayed in bold red in the main screen. Press r to switch to the request editor and edit the request. Press ENTER to stop editing and forward request.

Using custom proxy classes
====================================
Use the *launch* function to start sprox with a custom proxy class. It takes as arguments the port number and the custom proxy class. Both are keyword arguments - if unspecified, serv_port defaults to 50007 and custom_proxy_class defaults to None.

    from sprox import Proxy, launch
    
    class MyProxy(Proxy):
        ... #custom code
    
    launch(serv_port = 100000002, custom_proxy_class = MyProxy) #if not specified port defaults to 50007

To do
=====
  * Allow user to modify set timeouts on the fly
  * Improve requests editing
