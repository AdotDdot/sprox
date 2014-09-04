#!/usr/bin/env python
#
# sproxy-setup.py
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

from OpenSSL import crypto 
import os
import shutil
from sys import argv

localcert = argv[1] if len(argv) > 1 else "/etc/ssl/certs/ca-certificates.crt"
serial = int(argv[2]) if len(argv) > 2 else 1

#make files directory
files_dir = 'sproxy_files'
if os.path.isdir(files_dir): 
	shutil.rmtree(files_dir)
os.mkdir(files_dir)

#make sid file in files directory to store last used serial number
sid_file = os.path.join(files_dir, 'sid.txt')
with open(sid_file, 'w') as sid:
	sid.write('0')

#make file to store path to local certificates
loc_file = os.path.join(files_dir, 'localcerts.txt')
with open(loc_file, 'wt') as loc:
	loc.write(localcert)

#make root certificate in files directory
CERT_FILE = os.path.join(files_dir, "sproxy.pem")
KEY_FILE = os.path.join(files_dir, "sproxy.key")
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)
cert = crypto.X509()
cert.get_subject().O = "Sproxy"
cert.get_subject().OU = 'Sproxy Root CA'
cert.get_subject().CN = 'Sproxy Root CA'
cert.set_serial_number(serial)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10*365*24*60*60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha1')

with open(CERT_FILE, "wt") as cf: cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
with open(KEY_FILE, "wt") as kf: kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
print 'Setup completed'
