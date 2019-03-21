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

noinst_HEADERS	=	tcm_nvcommon.h

noinst_PROGRAMS =	tcm_startup	\
			tcm_reset

sbin_PROGRAMS	=	tcm_changeownerauth \
			tcm_clear	\
			tcm_createek	\
			tcm_getpubek    \
			tcm_restrictpubek \
			tcm_setactive	\
			tcm_setenable	\
			tcm_setclearable \
			tcm_setownable	\
			tcm_setpresence	\
			tcm_takeownership \
			tcm_version	\
			tcm_selftest

if TSM_LIB_IS_12
sbin_PROGRAMS  += 	tcm_nvdefine    \
			tcm_nvinfo      \
			tcm_nvread      \
			tcm_nvrelease   \
			tcm_nvwrite     \
			tcm_resetdalock \
			tcm_restrictsrk \
			tcm_revokeek \
			tcm_setoperatorauth
AM_CPPFLAGS	=	-I$(top_srcdir)/include -D_LINUX -DTSM_LIB_IS_12
else
AM_CPPFLAGS	=	-I$(top_srcdir)/include -D_LINUX
endif

LDADD		=	$(top_builddir)/lib/libtcm_tspi.la -ltcmspi @INTLLIBS@

tcm_startup_SOURCES =		tcm_startup.c
tcm_reset_SOURCES =		tcm_reset.c

tcm_changeownerauth_SOURCES =	tcm_changeauth.c
tcm_clear_SOURCES	=	tcm_clear.c
tcm_createek_SOURCES	=	tcm_createek.c
tcm_getpubek_SOURCES	=	tcm_getpubek.c
tcm_nvdefine_SOURCES	=	tcm_nvdefine.c tcm_nvcommon.c
tcm_nvinfo_SOURCES	=	tcm_nvinfo.c tcm_nvcommon.c
tcm_nvrelease_SOURCES	=	tcm_nvrelease.c tcm_nvcommon.c
tcm_nvread_SOURCES	=	tcm_nvread.c tcm_nvcommon.c
tcm_nvwrite_SOURCES	=	tcm_nvwrite.c tcm_nvcommon.c
tcm_restrictpubek_SOURCES =	tcm_restrictpubek.c
tcm_setactive_SOURCES	=	tcm_activate.c
tcm_setclearable_SOURCES =	tcm_clearable.c
tcm_setenable_SOURCES	=	tcm_enable.c
tcm_setownable_SOURCES	=	tcm_ownable.c
tcm_setpresence_SOURCES =	tcm_present.c
tcm_takeownership_SOURCES =	tcm_takeownership.c
tcm_version_SOURCES	=	tcm_version.c
tcm_selftest_SOURCES	=	tcm_selftest.c
tcm_revokeek_SOURCES	=	tcm_revokeek.c
tcm_setoperatorauth_SOURCES =   tcm_setoperatorauth.c
tcm_resetdalock_SOURCES =       tcm_resetdalock.c
tcm_restrictsrk_SOURCES =       tcm_restrictsrk.c

