#!/usr/bin/env python
#
# sprox.py
# Copyright (C) 2014 by A.D. <adotddot1123@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket
import sys
import threading
import ssl
import os
import argparse
import time
import urwid
import urlparse
from urllib import urlencode
from OpenSSL import crypto
from _abcoll import *
from operator import eq as _eq
from itertools import imap as _imap
try:
    from thread import get_ident as _get_ident
except ImportError:
    from dummy_thread import get_ident as _get_ident


class Proxy:
	def __init__(self, serv_port):
		self.serv_host = ''
		self.serv_port = serv_port
		self.max_listen = 300
		self.browser_timeout = 0.5
		self.web_timeout = 0.5
		self.buffer_size = 4096
		self._certfactory = CertFactory()
		self._init_localcert()
		#lists for output to the various screen of interface
                self.mainscreen_queue = []
                self.eventlog_queue = []
		self.intercepted_queue = []
                self.output_mode = 'b'
		self.interception_pattern = {'method':[], 'url':[], 'headers':[]}


	def modify_all(self, request):
		'''Override to apply changes to every request'''
		pass

	def parse_response(self, response, host):
		'''Override to handle received response - best used with concurrency'''
                pass

	def start(self):
		'''Start the proxy server'''
		try:
			serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			serv_sock.bind((self.serv_host, self.serv_port))
			serv_sock.listen(self.max_listen)
			cname = serv_sock.getsockname()
                        time.sleep(0.5)
			self.mainscreen_queue.append(('body', '\nProxy running on port %d - listening'%self.serv_port))
		except socket.error, (value, message):
			self._log(cname, ('err', 'Could not open server socket: error %d %s'%(value,message)))
			sys.exit(1)
		#mainloop
		while True:
			try:
				conn, addr = serv_sock.accept()
				self._log(cname, 'server connected by %s %s'%addr)
				conn_thread = threading.Thread(target = self._handle_conn, args = (conn,))
				conn_thread.daemon = 1
				try: conn_thread.start()
				except: conn.close()
			except KeyboardInterrupt:
				if conn: conn.close()
				self._certfactory.cleanup()
				serv_sock.close()
				exit(0)

	def _init_localcert(self):
		with open(os.path.join('sproxy_files', 'localcerts.txt'), 'rt') as loc:
			self.certfile = loc.read()

	def _handle_conn(self, conn):	
		#get request from browser
		conn.settimeout(self.browser_timeout)
                cname = conn.getsockname()
		request = self._recv_pipe('browser', conn)	
		if not request:
			self._log(cname, 'no request received from browser: closing socket')
			conn.close()
			sys.exit(1)	
		#process request to allow for user changes
		request_obj = HTTPRequest(request)
		self._handle_reqs(request_obj)
		request = request_obj.whole
		tunneling = request_obj.method == 'CONNECT'
		http_port = 443 if tunneling else 80
		http_host = request_obj.headers['Host']
		self._log(cname, 'got host %s, port %d'%(http_host, http_port))		
		#get and send response
		if tunneling: self._get_https_resp(http_host, http_port, conn)
		else: 
                        self._get_http_resp(http_host, http_port, conn, request, request_obj)
		conn.close()

	def _get_https_resp(self, host, port, conn):
                cname = conn.getsockname()
		conn.send(b'HTTP/1.1 200 Connection estabilished\n\n')
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		wclient = ssl.wrap_socket(wclient, server_side = False, ca_certs = self.certfile, cert_reqs = ssl.CERT_REQUIRED)
		try: wclient.connect((host, port))
		except ssl.SSLError, m: 
			self._log(cname, ('err', 'could not connect to %s: %s'%(host, m)))
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			self._log(cname, ('err', 'could not connect to %s: socket error %d %s'%(host, v, m)))
			wclient.close()
			conn.close()
			sys.exit(1)
		wclient.settimeout(self.web_timeout)
		#get server's certificate as pem 
		pem_data = ssl.DER_cert_to_PEM_cert(wclient.getpeercert(binary_form = True))	
		certfile, keyfile = self._certfactory.make_cert(pem_data)
		try: conn = ssl.wrap_socket(conn, server_side = True, certfile = certfile, keyfile= keyfile)
		except ssl.SSLError, m: 
			self._log(cname, ('err', 'could not complete ssl handshacke with browser client: %s'%m))
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (v, m):
			self._log(cname, ('err', 'could not complete ssl handshake with browser client: socket error %d - %s'%(v, m)))
			wclient.close()
			conn.close()
			sys.exit(1)
		#get plain text data
		request = self._recv_pipe(host, conn)
		if not request:
			wclient.close()
			conn.close()	
			sys.exit(1)	
		request_obj = HTTPRequest(request, https=True)
		self._handle_reqs(request_obj)
		request = request_obj.whole
		wclient.send(request)
		response = self._recv_pipe(host, wclient, conn)
		if response: 
			response_obj = HTTPResponse(response)
			self._handle_response(request_obj, response_obj, host)
		wclient.close()
		conn.close()
		
	def _get_http_resp(self, host, port, conn, req, req_obj):
                cname = conn.getsockname()
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._log(cname, 'client to host %s initialized'%host)
		wclient.settimeout(self.web_timeout)
		try:
			wclient.connect((host, port))
			self._log(cname, 'client to host %s connected'%host)
		except socket.timeout:
			self._log(cname, ('err', 'could not connect to %s: socket timed out'%host))
			wclient.close()
			conn.close()
			sys.exit(1)
		except socket.error, (value, message):
			self._log(cname, ('err', 'could not connect to %s: socket error error %d %s'%(host, value, message)))
			wclient.close()
			conn.close()
			sys.exit(1)
		wclient.send(req)
		self._log(cname, 'request sent to host %s'%host)
		response = self._recv_pipe(host, wclient, conn)
		if response:
			response_obj = HTTPResponse(response)
			self._handle_response(req_obj, response_obj, host)					
		wclient.close()
		self._log(cname, 'connection to client and connection to host %s closed'%host)

	def _recv_pipe(self, source, from_conn, to_conn = ''):
		msg = []
                cname = from_conn.getsockname()
		gotnull = 0
		while True:
			try:
				msg_pack = from_conn.recv(self.buffer_size)
			except ssl.SSLError, m:
				self._log(cname, 'ssl error occured while receiving data from %s: %s'%(source, m))
				break
			except socket.timeout:
				break
			except socket.error, (v, m):
				self._log(cname, 'socket error %d occurred while receiving data from %s - %s'%(v, source, m))
				break
			if not msg_pack:
				if gotnull: 
					break
				else: gotnull = 1
			else:
				msg.append(msg_pack)
				if to_conn:
					try: to_conn.send(msg_pack)
					except socket.error, (value, message):
						self._log(cname, 'could not send response from %s to %s: socket error %d - %s'%(source, (to_conn.getsockname()), value, message))
						from_conn.close()
						to_conn.close()
						sys.exit(1)
		return b''.join(msg)

	def _log(self, cname, content):
                self.eventlog_queue.append(['%f  '%time.time(), ('[%s %d]'%cname).ljust(25), content]) 

	def _matches_interception_pattern(self, request):
		'''Check if request matches intercepting pattern'''
		int_met = self.interception_pattern['method']
		int_url = self.interception_pattern['url']
		int_hdrs = self.interception_pattern['headers']
		if not int_met and not int_url and not int_hdrs: return False
		if (int_met and request.method not in int_met): return False
		if int_url:
			for pt in int_url: 
				if pt not in request.url: return False
		if int_hdrs: 
			for (k, v) in int_hdrs:
				try: 
					if v.lower() not in request.headers[k].lower(): return False
				except KeyError: continue
		return True

	def _handle_reqs(self, request):
		'''Apply changes to incoming requests'''
		#apply all-requests changes
		self.modify_all(request)
		request.whole = request.make_raw()
		#block requests that match interception pattern to allow user changes
		if self._matches_interception_pattern(request):
			request.on_hold = True
			self.intercepted_queue.append(request)
			self.mainscreen_queue.append(('bred', '\n'+request.first_line))
		while request.on_hold: 
			time.sleep(1)
		       
	def _handle_response(self, request, response, host):
		'''After response has been received'''
                self._output_flow(request, response)
                self.parse_response(response, host)

        def _output_flow(self, request, response):
		'''Output request and response'''
                #set palette attr for request method
                if request.method == 'GET':
                        metcol = 'bblue'
                elif request.method == 'POST':
                        metcol = 'byellow'
                else:
                        metcol = 'err'
                #set palette attr for response code
                if response.status[0] == '2':
                        statcol = 'pgreen'
                elif response.status[0] == '3':
                        statcol = 'pcyan'
                elif response.status[0] == '4':
                        statcol = 'err'
                elif response.status[0] == '5':
                        statcol = 'pyellow'
                else:
                        statcol = 'pmagenta'
		#output in basic mode
                if self.output_mode == 'b':
                        clength = response.headers['Content-Length']+' bytes' if 'Content-Length' in response.headers else ''
		        ctype = response.headers['Content-Type'] if 'Content-Type' in response.headers else ''
			out = ['\n', (metcol, request.method), ' ', request.url, ' ', request.protov, '\n    ',
                                response.protov, ' ', (statcol, '%s %s'%(response.status, response.status_text)), ' %s %s'%(clength, ctype)]
		#output in full mode
                elif self.output_mode == 'f':
                        out = ['\n\n', (metcol, request.method), ' ', request.url, ' ', request.protov, request.head.replace(request.first_line, '')]
                        if request.body:
				out.append(('pyellow', request.decoded_body))
                        out.append(('body', '\n\n'+response.head.replace('\r', '\n').replace('\n\n', '\n')))
		#append to queue
                self.mainscreen_queue.append(out)                        


class HTTPRequest:
	def __init__(self, raw_req, https = False):
		self.https = https
		self.on_hold = False
		self.whole = raw_req.replace('\r', '\n').replace('\n\n', '\n')
		self._set_parts()
		self._decode_body()

	def _set_parts(self):
                self.head, self.body = self.whole.split('\n\n')
		self.first_line = str(self.head).splitlines()[0]
		self.headers = HeaderDict([x.split(': ', 1) for x in self.head.splitlines()[1:]])
                self.method, self.url, self.protov = self.first_line.split(' ', 2)
		if self.https: self.url = 'https://'+self.headers['host']+self.url

	def _decode_body(self): 
		if self.body and 'Content-Type' in self.headers and 'application/x-www-form-urlencoded' in self.headers['Content-Type']:
				self.decoded_body = '\n'.join(['[Url-encoded]']+[': '.join(t) for t in urlparse.parse_qsl(self.body.strip('\n'))])
				self._body_decoded = True
		else:
			self.decoded_body = self.body
			self._body_decoded = False

	def _reencode_body(self, new_body):
		'''Used after the body of a request has been altered in a request editor. 
		If the body displayed had been decoded, it is encoded, else it is left as it is'''
		if not self._body_decoded: return new_body
		else:
			return urlencode([tuple(x.split(': ', 1)) for x in new_body.splitlines()[1:]])

	def reset_request(self, editor_content):
		'''Used after a request has been altered in a request editor.
		Reset all parts'''
		head, body = editor_content.split('\n\n', 1)
		self.whole = '\n\n'.join([head, self._reencode_body(body)])
		self._set_parts()	

	def set_header(self, header, value):
		self.headers[header] = value
		headers = '\n'.join([header+': '+self.headers[header] for header in self.headers])
		self.head = '\n'.join([self.first_line, headers])
		
	def make_raw(self):
		#put all parts back together
		parsed = urlparse.urlparse(self.url)
		url = self.url.replace(parsed.scheme+'://'+parsed.netloc, '', 1)
		first_line = ' '.join([self.method, url, self.protov])
		headers = '\r\n'.join([header+': '+self.headers[header] for header in self.headers])
		head = '\r\n'.join([first_line, headers]) 
		return '\r\n\r\n'.join([head, self.body]) 


class HTTPResponse:
	def __init__(self, raw_resp):
		self.raw = raw_resp
		self._set_parts()

	def _set_parts(self):
		self.head = str(self.raw.replace(b'\r\n\r\n', b'\n\n').replace(b'\n\r\n\r', b'\n\n')).split('\n\n', 2)[0]
		self.body = self.raw.replace(self.head.encode(), b'').replace('\n\n', '')
		self.first_line = self.head.splitlines()[0]
		self.headers = HeaderDict(x.split(': ', 1) for x in self.head.splitlines()[1:])
		self.protov, self.status, self.status_text = self.first_line.split(' ', 2)


class CertFactory:
	def __init__(self):
		self._files_dir = 'sproxy_files'
		self._sid = os.path.join(self._files_dir,'sid.txt')
		with open(self._sid, 'rt') as sid: self._count = int(sid.read())
		self._count_lock = threading.Lock()
		self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(os.path.join(self._files_dir, 'sproxy.pem')).read())
		self.root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(os.path.join(self._files_dir, 'sproxy.key')).read())
		self.issuer= self.root_cert.get_subject()
			
	def make_cert(self, pem_data):
		old_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
		common_name = old_cert.get_subject().CN	
		if os.path.isfile(os.path.join(self._files_dir, common_name+'.pem')):
			certfile = os.path.join(self._files_dir, common_name+'.pem')
			keyfile = os.path.join(self._files_dir, common_name+'.key')
			return certfile, keyfile
		pkey = crypto.PKey()
		pkey.generate_key(crypto.TYPE_RSA, 2048)
		new_cert = crypto.X509()
		new_cert.gmtime_adj_notBefore(0)
		new_cert.gmtime_adj_notAfter(10*365*24*60*60)
		#set same subject of old cert
		new_cert.set_subject(old_cert.get_subject())
		#look for and set SNA of old cert
		for i in range(old_cert.get_extension_count()):
			ext = old_cert.get_extension(i)
			if ext.get_short_name() == 'subjectAltName':
				new_cert.add_extensions([ext])
		new_cert.set_issuer(self.issuer)
		self._count_lock.acquire()
		new_cert.set_serial_number(self._count)
		self._count += 1
		self._count_lock.release()		
		new_cert.set_pubkey(pkey)
		new_cert.sign(self.root_key, 'sha1')
		certfile = os.path.join( self._files_dir, common_name+'.pem',)
		keyfile = os.path.join( self._files_dir, common_name+'.key')		
		#write key and cert
		with open(certfile, "wt") as cf: cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, new_cert))
		with open(keyfile, "wt") as kf: kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
		#append root to cert chain
		with open(certfile, 'at') as ccf: ccf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.root_cert)) 		
		return certfile, keyfile

	def cleanup(self):
		#update count of last serial number used
		with open(self._sid, 'wt') as sid:
			self._count_lock.acquire()
			sid.write(str(self._count))
			self._count_lock.release()


class HeaderDict(dict):
    '''Caseless Ordered Dictionary
    Enables case insensitive searching and updating while preserving case sensitivity when keys are listed.
    Combination of the code of collections.OrderedDict and CaselessDictionary (https://gist.github.com/bloomonkey/3003096) '''
    
    def __init__(self, *args, **kwds):
        if len(args) > 1:
            raise TypeError('expected at most 1 arguments, got %d' % len(args))
        try:
            self.__root
        except AttributeError:
            self.__root = root = []                   
            root[:] = [root, root, None]
            self.__map = {}
        self.__update(*args, **kwds)

    def __contains__(self, key):
        return dict.__contains__(self, key.lower())
  
    def __getitem__(self, key):
        return dict.__getitem__(self, key.lower())['val'] 

    def __setitem__(self, key, value, dict_setitem=dict.__setitem__):
        if key not in self:
            root = self.__root
            last = root[0]
            last[1] = root[0] = self.__map[key] = [last, root, key]
        return dict.__setitem__(self, key.lower(), {'key': key, 'val': value})

    def __delitem__(self, key, dict_delitem=dict.__delitem__):
        dict_delitem(self, key)
        link_prev, link_next, _ = self.__map.pop(key)
        link_prev[1] = link_next                        
        link_next[0] = link_prev                       

    def __iter__(self):
        root = self.__root
        curr = root[1]                                  
        while curr is not root:
            yield curr[2]                              
            curr = curr[1]                         

    def __reversed__(self):
        root = self.__root
        curr = root[0]                                
        while curr is not root:
            yield curr[2]                             
            curr = curr[0]                       

    def clear(self):
        root = self.__root
        root[:] = [root, root, None]
        self.__map.clear()
        dict.clear(self)

    def keys(self):
        return list(self)

    def values(self):
        return [self[key] for key in self]

    def items(self):
        return [(key, self[key]) for key in self]

    def iterkeys(self):
        return iter(self)

    def itervalues(self):
        for k in self:
            yield self[k]

    def iteritems(self):
        for k in self:
            yield (k, self[k])

    def get(self, key, default=None):
        try:
            v = dict.__getitem__(self, key.lower())
        except KeyError:
            return default
        else:
            return v['val']

    def has_key(self,key):
        return key in self

    update = MutableMapping.update

    __update = update 

    __marker = object()

    def pop(self, key, default=__marker):
        if key in self:
            result = self[key]
            del self[key]
            return result
        if default is self.__marker:
            raise KeyError(key)
        return default

    def setdefault(self, key, default=None):
        if key in self:
            return self[key]
        self[key] = default
        return default

    def popitem(self, last=True):
        if not self:
            raise KeyError('dictionary is empty')
        key = next(reversed(self) if last else iter(self))
        value = self.pop(key)
        return key, value

    def __repr__(self, _repr_running={}):
        call_key = id(self), _get_ident()
        if call_key in _repr_running:
            return '...'
        _repr_running[call_key] = 1
        try:
            if not self:
                return '%s()' % (self.__class__.__name__,)
            return '%s(%r)' % (self.__class__.__name__, self.items())
        finally:
            del _repr_running[call_key]

    def __reduce__(self):
        items = [[k, self[k]] for k in self]
        inst_dict = vars(self).copy()
        for k in vars(OrderedDict()):
            inst_dict.pop(k, None)
        if inst_dict:
            return (self.__class__, (items,), inst_dict)
        return self.__class__, (items,)

    def copy(self):
        return self.__class__(self)

    @classmethod
    def fromkeys(cls, iterable, value=None):
        self = cls()
        for key in iterable:
            self[key] = value
        return self

    def __eq__(self, other):
        if isinstance(other, OrderedDict):
            return dict.__eq__(self, other) and all(_imap(_eq, self, other))
        return dict.__eq__(self, other)

    def __ne__(self, other):
        return not self == other

    def viewkeys(self):
        return KeysView(self)

    def viewvalues(self):
        return ValuesView(self)

    def viewitems(self):
        return ItemsView(self)

################################################################ urwid 

class EEdit(urwid.Edit):
	'''An Edit widget that emits a custom signal on enter'''
	def keypress(self, size, key):
		if key == 'enter': 
			urwid.emit_signal(self, 'done')
		urwid.Edit.keypress(self, size, key) 
	
class Interface:
	palette = [
		('body', 'white', 'black'),
                ('bwhite', 'white, bold', 'black'),
                ('pgrey', 'dark gray', 'black'),
                ('bgrey', 'dark gray', 'black'),
		('ext', 'white', 'dark blue'),
		('ext_hi', 'light cyan, bold', 'dark blue'),
                ('pgreen', 'light green', 'black'),
                ('bblue', 'light blue, bold', 'black'),
                ('byellow', 'yellow, bold', 'black'),
                ('pcyan', 'dark cyan', 'black'),
                ('pyellow', 'yellow', 'black'),
                ('pmagenta', 'dark magenta', 'black'),
                ('err', 'light red', 'black'),
		('bred', 'light red, bold', 'black'),
		]

	header_text = [
		('ext_hi', '  ESC'), ':quit        ',
		('ext_hi', 'UP'), ',', ('ext_hi', 'DOWN'), ':scroll        ',
                ('ext_hi', 'b'), ',', ('ext_hi', 'f'), ':output mode        ',
                ('ext_hi', 'l'), ':event log        ',
                ('ext_hi', 'm'), ':main screen        ',
		('ext_hi', 'r'), ':request editor',          
		]

	def __init__(self, serv_port):
		self._init_iparser()
		self.header = urwid.AttrWrap(urwid.Text(self.header_text), 'ext')
                self.footer = EEdit("  Current interception pattern: ")
		self.flowWalker = urwid.SimpleListWalker([])
		self.mscreen = urwid.ListBox(self.flowWalker)
                self.logWalker = urwid.SimpleListWalker([])
                self.eventlog = urwid.ListBox(self.logWalker)
		self.reqEdit = urwid.WidgetPlaceholder(urwid.Filler(urwid.Text(('ext', ' No requests intercepted yet '), align='center'), 'middle'))
		self.reqEditor = EEdit("", multiline=False)
		self.editor_locked = False
                self.body = urwid.WidgetPlaceholder(self.mscreen)
		self.view = urwid.Frame(
			urwid.AttrWrap(self.body, 'body'),
			header = self.header,
			footer = urwid.AttrWrap(self.footer, 'ext'))
		urwid.register_signal(EEdit, ['done'])
		urwid.connect_signal(self.footer, 'done', self._on_pattern_set)
		urwid.connect_signal(self.reqEditor, 'done', self._on_req_modified)
		self.loop = urwid.MainLoop(self.view, self.palette, 
			unhandled_input = self.unhandled_input)
                self.proxy = Proxy(serv_port)

	def start(self):
		t = threading.Thread(target = self._fill_screen)
		t.daemon = 1
		t2 = threading.Thread(target = self.proxy.start)
		t2.daemon = 1
		t.start()
		t2.start()
		self.loop.run()

	def unhandled_input(self, k):
		if k == 'esc':
                        self.proxy._certfactory.cleanup()
			raise urwid.ExitMainLoop()
                #set output preference		
                elif k in ('B', 'b'):
                        self.proxy.output_mode = 'b'
                elif k in ('F', 'f'):
                        self.proxy.output_mode = 'f'
		#switch between screens
                elif k in ('l', 'L'):
                        self.body.original_widget = self.eventlog
                elif k in ('m', 'M'):
                        self.body.original_widget = self.mscreen
		elif k in ('r', 'R'):
			self.body.original_widget = self.reqEdit

	def _init_iparser(self):
		self.iparser = argparse.ArgumentParser()
		self.iparser.add_argument('-m', nargs='*')
		self.iparser.add_argument('-u', nargs='*')
		self.iparser.add_argument('-e', type=self._header_type, nargs='*')
		self.correspondences = {'g':'GET', 'p':'POST', 'd':'DELETE', 't':'TRACE', 'u':'PUT', 'o':'OPTIONS', 'h':'HEAD', 'c':'CONNECT'}

	def _header_type(self, s):
		try: 
			k, v = s.split('=')
			return (k, v)
		except: raise argparse.ArgumentTypeError("")

	def _fill_screen(self):	
		#infinite loop - check every 0.5s if there is something to output
		while 1:
			if self.proxy.mainscreen_queue:
                                for i in self.proxy.mainscreen_queue:
				        self.flowWalker.append(urwid.Padding(urwid.Text(self.proxy.mainscreen_queue.pop(0)), left = 2))
				try:
					self.loop.draw_screen()
					self.mscreen.set_focus(len(self.flowWalker)-1, 'above')
				except AssertionError: pass
                        if self.proxy.eventlog_queue:
                                for i in self.proxy.eventlog_queue:
				        self.logWalker.append(urwid.Padding(urwid.AttrWrap(urwid.Text(self.proxy.eventlog_queue.pop(0)), 'pgrey'), left = 2))
				try:
					self.loop.draw_screen()
					self.eventlog.set_focus(len(self.logWalker)-1, 'above')
				except AssertionError: pass
			if self.proxy.intercepted_queue:
				if not self.editor_locked:
					self.editor_locked = True
					request = self.proxy.intercepted_queue[0]
					self.reqEditor.set_edit_text(request.head+'\n\n'+request.decoded_body)
					self.reqEdit.original_widget = urwid.Filler(urwid.Padding(urwid.LineBox(self.reqEditor, title='Editing request:'), left=5, right=5), 'middle')
					self.loop.draw_screen()	
                        time.sleep(0.5)
					

	def _on_pattern_set(self):
		#parse and set pattern
		try:
			opts = self.iparser.parse_args(self.footer.get_edit_text().split())
			try:
				self.proxy.interception_pattern['method'] = [self.correspondences[mt] for mt in opts.m]
			except: self.proxy.interception_pattern['method'] = []
			self.proxy.interception_pattern['url'] = opts.u	
			try: self.proxy.interception_pattern['headers'] = opts.e
			except: self.proxy.interception_pattern['headers'] = [] 
		except: pass
		#remove cursor
		self.view.focus_position = 'body'

	def _on_req_modified(self):
		request = self.proxy.intercepted_queue.pop(0)
		#replace request attributes
		request.reset_request(self.reqEditor.get_edit_text())
		self.reqEdit.original_widget = urwid.Filler(urwid.Text(''), 'middle')
		request.on_hold = False
		self.editor_locked = False
		self.view_focus_position = 'body'
		                     

if __name__ == '__main__':
	serv_port = sys.argv[1] if len(sys.argv) > 1 else 50007
        i = Interface(serv_port)
        i.start()
