#
# Makefile.am
#
#       The Initial Developer of the Original Code is International
#       Business Machines Corporation. Portions created by IBM
#       Corporation are Copyright (C) 2005, 2006 International Business
#       Machines Corporation. All Rights Reserved.
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the Common Public License as published by
#       IBM Corporation; either version 1 of the License, or (at your option)
#       any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       Common Public License for more details.
#
#       You should have received a copy of the Common Public License
#       along with this program; if not, a copy can be viewed at
#       http://www.opensource.org/licenses/cpl1.0.php.
#

bin_PROGRAMS	=	tcmtoken_init		\
			tcmtoken_setpasswd	\
			tcmtoken_objects	\
			tcmtoken_import		\
			tcmtoken_protect

noinst_HEADERS =	data_common.h \
			data_import.h \
			data_init.h \
			data_object.h \
			data_passwd.h \
			data_protect.h

#
# Common build flags
AM_CPPFLAGS	=	-I$(top_srcdir)/include -D_LINUX

LDADD		=	$(top_builddir)/lib/libtcm_pkcs11.la -ltcmspi -ldl @INTLLIBS@


#
# TCM Token initialization command
tcmtoken_init_SOURCES		=	data_init.c

#
# TCM Token change password command
tcmtoken_setpasswd_SOURCES	=	data_passwd.c

#
# TCM Token object list command
tcmtoken_objects_SOURCES	=	data_object.c

#
# TCM Token object import command
tcmtoken_import_SOURCES		=	data_import.c
tcmtoken_import_LDADD		=	$(LDADD) -lcrypto

#
# TCM Token data protection command
tcmtoken_protect_SOURCES	=	data_protect.c
