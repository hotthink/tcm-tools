#
# Makefile.am
#
#       The Initial Developer of the Original Code is International
#       Business Machines Corporation. Portions created by IBM
#       Corporation are Copyright (C) 2005 International Business
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

man8_PODS =

if TSM_LIB_IS_12
man8_PODS +=	tcm_nvdefine.pod	\
		tcm_nvinfo.pod		\
		tcm_nvread.pod		\
		tcm_nvrelease.pod	\
		tcm_nvwrite.pod
endif

man8_MANS =	tcm_changeownerauth.8	\
		tcm_clear.8		\
		tcm_createek.8		\
		tcm_getpubek.8		\
		tcm_restrictpubek.8	\
		tcm_selftest.8		\
		tcm_setactive.8		\
		tcm_setclearable.8	\
		tcm_setenable.8		\
		tcm_setownable.8	\
		tcm_setpresence.8	\
		tcm_takeownership.8	\
		$(addsuffix .8,$(basename $(man8_PODS)))

if TSM_LIB_IS_12
man8_MANS+=tcm_revokeek.8 tcm_setoperatorauth.8 tcm_resetdalock.8
endif

EXTRA_DIST = $(man8_MANS)

%.8 : %.pod
	@pod2man -r "TCM Management" \
		-c "" \
		-n $(basename $@) \
		--section=8 $< > $@
