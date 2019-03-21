/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005, 2006 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

#ifndef __TCM_SEAL_H
#define __TCM_SEAL_H

#define TCMSEAL_HDR_STRING "-----BEGIN TSM-----\n"
#define TCMSEAL_FTR_STRING "-----END TSM-----\n"
#define TCMSEAL_TSM_STRING "-----TSM KEY-----\n"
#define TCMSEAL_EVP_STRING "-----ENC KEY-----\n"
#define TCMSEAL_ENC_STRING "-----ENC DAT-----\n"

#define TCMSEAL_KEYTYPE_SYM "Symmetric Key: "
#define TCMSEAL_CIPHER_AES256CBC "AES-256-CBC\n"

#define TCMSEAL_SECRET "password"
#define TCMSEAL_IV "IBM SEALIBM SEAL"
#endif
