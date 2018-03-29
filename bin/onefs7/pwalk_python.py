#!/usr/bin/python

# Version: pwalk_python.py for pwalk 1.97b

# Read <LIN> or <PATHNAME> from stdin, and return formatted DOMAIN and WORM info.
# Used by pwalk as a co-process via pipe I/O, but also can be used as a command-line utility.
#	eg: find <SmartLock_Directory> -type f | ./pwalk_python.py [-v]

import isi.fs.domain as domain
import sys
import errno
import os
import time
import json

# Force I/O to be unbuffered (incantation found online) ...
buf_arg = 0
if sys.version_info[0] == 3:
    os.environ['PYTHONUNBUFFERED'] = 1
    buf_arg = 1
sys.stdin = os.fdopen(sys.stdin.fileno(), 'r', buf_arg)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'a+', buf_arg)
sys.stderr = sys.stdout

WORM_RETAIN_EXPIRE_NOW = 0
WORM_RETAIN_FOREVER = 0x7FFFFFFFFFFFFFFEL
WORM_RETAIN_USE_MIN = 1
WORM_RETAIN_USE_MAX = 2

try:
	if (sys.argv[1] == '-v'): verbose = 1
	elif (sys.argv[1] == '-vv'): verbose = 2
except:
	verbose = 0

def dump_info():
	print
	print 'DOMAIN INFO:'
	flags = domain_info['flags']
	print '              flags = 0x'+format(flags,'X'),
	if (flags & 0x80000000): print 'DOM_READY',		# (1 << 31)
	if (flags & 0x00000080): print 'DOM_SNAPREVERT',	# (1 << 7) 1000.0000
	if (flags & 0x00000040): print 'DOM_PRIVDEL_DISABLED',	# (1 << 6) 0100.0000
	if (flags & 0x00000020): print 'DOM_PRIVDEL_ON',	# (1 << 5) 0010.0000
	if (flags & 0x00000008): print 'DOM_SYNCIQ',		# (1 << 3) 0000.1000
	if (flags & 0x00000004): print 'DOM_COMPLIANCE',	# (1 << 2) 0000.0100
	if (flags & 0x00000002): print 'DOM_WORM',		# (1 << 1) 0000.0010
	if (flags & 0x00000001): print 'DOM_RESTRICTED_WRITE',	# (1 << 0) 0000.0000
	print
	print '                 id =',domain_info['id']
	print '         generation =',domain_info['generation']
	print '           root_lin =',domain_info['root_lin']
	print '      w_auto_offset =',domain_info['autocommit_offset']
	print '       w_min_offset =',domain_info['min_offset']
	print '       w_max_offset =',domain_info['max_offset']
	print '       w_def_offset =',domain_info['default_offset']
	print '    w_override_date =',domain_info['override_retention']
	print
	print 'FILE INFO:'
	print '                lin =',lin
	print '         w_ref_date =',w_ref_date
	try:
		statbuf.st_atime
		print '           st_atime =',statbuf.st_atime,'(',time.ctime(statbuf.st_atime),')'
		print '           st_mtime =',statbuf.st_mtime,'(',time.ctime(statbuf.st_mtime),')'
		print '           st_ctime =',statbuf.st_ctime,'(',time.ctime(statbuf.st_ctime),')'
		print '       st_birthtime =',statbuf.st_birthtime,'(',time.ctime(statbuf.st_birthtime),')'
	except:
		pass
	print
	print 'FILE WORM INFO:'
	print '        w_committed =',worm_state['committed']
	print '            w_ctime =',worm_state['ctime']
	print '   w_retention_date =',worm_state['retention_date']
	print
	print 'COLUMN HEADING:'
	print 'py_p py_rc py_errno w_ref_date w_committed w_ctime w_retention_date w_auto_offset w_min_offset w_max_offset w_def_offset w_override_date'

while 1:
	arg = sys.stdin.readline().rstrip('\n')
	if arg == '':
		break

	# If it's an int, assume it's a LIN, otherwise a pathname ...
	# Minus 1 is a signal to exit ...
	try:
		lin = int(arg)
		if lin == -1:
			exit()
	except:
		try:
			statbuf = os.lstat(arg)
			lin = statbuf.st_ino
		except:
			print 'P',-1,0,'os.lstat() error'		# @@
			continue

	# Get the domain info ...
	# FUTURE: For Compiance-mode domain, fetch w_ref_date as Compliance clock
	try:
		domain_info = domain.get_domain_info_by_lin(lin,-1)
		w_ref_date = int(time.time())
	except ValueError as e:
		print 'P',-2,e.errno,'ValueError:'			# @@
		continue
	except OSError, e:
		print 'P',-3,e.errno,'OSError:',os.strerror(e.errno)	# @@
		continue
	except IOError, e:
		print 'P',-3,e.errno,'IOError:',os.strerror(e.errno)	# @@
		continue

	# '-v' verbose print domain info ... '-vv' formats it  ...
	if verbose == 1:
		print domain_info
	elif verbose == 2:
		print json.dumps(domain_info, indent=4, separators=(',', ': '))

	# Only SmartLock DIRECTORIES have worm_ancestors[] ...
	try:
		domain_info['worm_ancestors'][0]
		print 'P',-4,0,'SKIPPING SMARTLOCK DIRECTORY'		# @@
		continue
	except:
		pass

	# Focus to simplify addressing ...
	try:
		worm_state = domain_info['worm_state']
		domain_info = domain_info['domains'][0]
	except:
		print 'P',-5,0,'NOT A SMARTLOCK FILE OR DIRECTORY'	# @@
		continue

	if verbose: dump_info()

	# Single line of output ...					# @@
	print 'P',
	print 0,
	print 0,
	print w_ref_date,
	print worm_state['committed'],
	print worm_state['ctime'],
	print worm_state['retention_date'],
	print domain_info['autocommit_offset'],
	print domain_info['min_offset'],
	print domain_info['max_offset'],
	print domain_info['default_offset'],
	print domain_info['override_retention']
