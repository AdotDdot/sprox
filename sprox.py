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
import time
import urwid
import urlparse
from OpenSSL import crypto
from codict import COD as HeaderDict

class Proxy:
	def __init__(self, serv_port = 50007):
		self.serv_host = ''
		self.serv_port = serv_port
		self.max_listen = 300
		self.blacklist = []
		self.browser_timeout = 1
		self.web_timeout = 1
		self.buffer_size = 4096
		self.debug = False
		self.stdout_lock = threading.Lock()
		self._certfactory = CertFactory()
		self._init_localcert()
                self.mainscreen_queue = []
                self.eventlog_queue = []
                self.output_mode = 'b'

        def out(self, content):
                self.mainscreen_queue.append(content)

	def modify_reqs(self, request):
		pass

        def parse_response(self, response, host):
                pass

	def on_response(self, request, response, host, https = False):
                self.output_flow(request, response, host, https)
                self.parse_response(response, host)

        def output_flow(self, request, response, host, https):
                #url to display
                url = 'https://'+host+request.url if https else request.url
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
                        statcol = 'pred'
                elif response.status[0] == '5':
                        statcol = 'pyellow'
                else:
                        statcol = 'pmagenta'
                if self.output_mode == 'b':
                        clength = response.headers['Content-Length']+' bytes' if 'Content-Length' in response.headers else ''
		        ctype = response.headers['Content-Type'] if 'Content-Type' in response.headers else ''
                        out = ['\n', (metcol, request.method), ' ', url, ' ', request.protov, '\n    ',
                                response.protov, ' ', (statcol, '%s %s'%(response.status, response.status_text)), ' %s %s'%(clength, ctype)]
                        #outresp = ('body', '    %s  %s  %s'%(response.first_line, clength, ctype))
                elif self.output_mode == 'f':
                        out = ['\n\n', (metcol, request.method), ' ', url, ' ', request.protov, request.head.replace(request.first_line, '')]
                        if request.method == 'POST':
                                if 'Content-Type' in request.headers and 'application/x-www-form-urlencoded' in request.headers['Content-Type']:
                                        out.append(('pyellow', '\n'.join(['\nUrl-encoded form:']+[': '.join(t) for t in urlparse.parse_qsl(request.body.strip('\n'))])))
                                else: 
                                        out.append(('pyellow', '\nPost data:\n%s'%request.body))

                        out.append(('body', '\n\n'+response.head.replace('\r', '\n').replace('\n\n', '\n')))
                self.stdout_lock.acquire()
                self.out(out)
                self.stdout_lock.release()
		
	def start(self):
		try:
			serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			serv_sock.bind((self.serv_host, self.serv_port))
			serv_sock.listen(self.max_listen)
			cname = serv_sock.getsockname()
                        time.sleep(0.5)
			self.out(('body', '\nProxy running on port %d - listening'%self.serv_port))
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
		conn.settimeout(self.browser_timeout)
                cname = conn.getsockname()
		request = self._recv_pipe('browser', conn)	
		if not request:
			self._log(cname, 'no request received from browser: closing socket')
			conn.close()
			sys.exit(1)	
		#process request to allow for user changes
		request_obj = HTTPRequest(request)
		self.modify_reqs(request_obj)
		request = request_obj.make_raw()
		tunneling = request_obj.method == 'CONNECT'
		http_port = 443 if tunneling else 80
		http_host = request_obj.headers['Host']
		self._log(cname, 'got host %s, port %d'%(http_host, http_port))
		#check blacklist
		if http_host in self.blacklist:
			self._log(cname, 'host in blacklist: closing connection')
			conn.close()
			sys.exit(1) 		
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
		request_obj = HTTPRequest(request)
		self.modify_reqs(request_obj)
		request = request_obj.make_raw()
		wclient.send(request)
		try: 
			response = self._recv_pipe(host, wclient, conn)
			if response: 
				response_obj = HTTPResponse(response)
				self.on_response(request_obj, response_obj, host, https = True)
		except ssl.SSLError, m: self._log(cname, '%s'%m) #watch
		except socket.error, (v, m): self._log(cname, host+ ' - Error '+str(v)+' '+m) #watch
		finally:
			wclient.close()
			conn.close()
		
	def _get_http_resp(self, host, port, conn, req, req_obj):
                cname = conn.getsockname()
		wclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._log(cname, 'client to host %s initialized'%host)
		wclient.settimeout(self.web_timeout)
		try:
			hostip = socket.gethostbyname(host)
			wclient.connect((hostip, port))
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
			self.on_response(req_obj, response_obj, host)					
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
				#self._log(cname, 'socket timed out while receiving data: breaking receiving loop')
				break
			except socket.error, (v, m):
				self._log(cname, 'socket error %d occurred while receiving data from %s - %s'%(v, source, m))
				break
			if not msg_pack:
				if gotnull: 
					#self._log(cname, 'end of data: breaking receiving loop') 
					break
				else: gotnull = 1
			else:
				#self._log('[%s %d]  got data packet of len %d'%(cname[0], cname[1], len(msg_pack)))
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
                '''
                        self.stdout_lock.acquire()
                        self.out(('pgrey', ' '.join([str(arg) for arg in args])))
                        self.stdout_lock.release()'''





class HTTPRequest:
	def __init__(self, raw_req):
		self.whole = raw_req.replace('\r', '\n').replace('\n\n', '\n')
		self._set_parts()

	def _set_parts(self):
                self.head, self.body = self.whole.split('\n\n')
		self.first_line = str(self.head).splitlines()[0]
		self.headers = HeaderDict([x.split(': ', 1) for x in self.head.splitlines()[1:]])
                self.method, self.url, self.protov = self.first_line.split(' ', 2)

	def set_header(self, header, value):
		self.headers[header] = value
		headers = '\n'.join([header+': '+self.headers[header] for header in self.headers])
		self.head = '\n'.join([self.first_line, headers])
		
	def make_raw(self):
		first_line = ' '.join([self.method, self.url, self.protov])
		headers = '\r\n'.join([header+': '+self.headers[header] for header in self.headers])
		head = '\r\n'.join([first_line, headers]) 
		return '\r\n\r\n'.join([head, self.body]) #TODO head.encode?


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
		with open(self._sid, 'wt') as sid:
			self._count_lock.acquire()
			sid.write(str(self._count))
			self._count_lock.release()


class Interface:
	palette = [
		('body', 'white', 'black'),
                ('bwhite', 'white, bold', 'black'),
                ('pgrey', 'dark gray', 'black'),
                ('bgrey', 'dark gray', 'black'),
		('ext', 'white', 'dark blue'),
		('ext_hi', 'light cyan, bold', 'dark blue'),
                ('pgreen', 'light green', 'black'),
                #('pgreen', 'light green', 'black'),
                ('bblue', 'light blue, bold', 'black'),
                #('pblue', 'light blue', 'black'),
                ('byellow', 'yellow, bold', 'black'),
                ('pcyan', 'dark cyan', 'black'),
                ('pred', 'light red', 'black'),
                ('pyellow', 'yellow', 'black'),
                ('pmagenta', 'dark magenta', 'black'),
                ('err', 'light red', 'black'),
		]

	header_text = [
		('ext_hi', '  ESC'), ':quit        ',
		('ext_hi', 'UP'), ',', ('ext_hi', 'DOWN'), ':scroll        ',
                ('ext_hi', 'b'), ',', ('ext_hi', 'f'), ':output mode        ',
                ('ext_hi', 'l'), ':event log        ',
                ('ext_hi', 'm'), ':main screen'
                
		]

	def __init__(self):
		self.header = urwid.AttrWrap(urwid.Text(self.header_text), 'ext')
                self.footer = urwid.Text("  Output: basic")
		self.flowWalker = urwid.SimpleListWalker([])
		self.mscreen = urwid.ListBox(self.flowWalker)
                self.logWalker = urwid.SimpleListWalker([])
                self.eventlog = urwid.ListBox(self.logWalker)
                self.body = urwid.WidgetPlaceholder(self.mscreen)
		self.view = urwid.Frame(
			urwid.AttrWrap(self.body, 'body'),
			header = self.header,
			footer = urwid.AttrWrap(self.footer, 'ext'))
		self.loop = urwid.MainLoop(self.view, self.palette, 
			unhandled_input = self.unhandled_input)
                self.proxy = Proxy()
                self.proxy.debug = 0 #TEST


	def start(self):
		t = threading.Thread(target = self.fill_screen)
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
                        self.footer.set_text('  Output: basic')
                elif k in ('F', 'f'):
                        self.proxy.output_mode = 'f'
                        self.footer.set_text('  Output: full')
                elif k in ('l', 'L'):
                        self.body.original_widget = self.eventlog
                elif k in ('m', 'M'):
                        self.body.original_widget = self.mscreen

	def fill_screen(self):	
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
                        time.sleep(0.5)
                        


if __name__ == '__main__':
        i = Interface()
        i.start()
