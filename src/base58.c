/*******************************************************************************
*   HODL Application
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "base58.h"

unsigned char const N_BTC_BASE58_ALPHABET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

unsigned char const N_XRP_BASE58_ALPHABET[] = {
    'r', 'p', 's', 'h', 'n', 'a', 'f', '3', '9', 'w', 'B', 'U', 'D', 'N', 'E',
    'G', 'H', 'J', 'K', 'L', 'M', '4', 'P', 'Q', 'R', 'S', 'T', '7', 'V', 'W',
    'X', 'Y', 'Z', '2', 'b', 'c', 'd', 'e', 'C', 'g', '6', '5', 'j', 'k', 'm',
    '8', 'o', 'F', 'q', 'i', '1', 't', 'u', 'v', 'A', 'x', 'y', 'z'};

unsigned char hodl_encode_base58(unsigned char WIDE *alphabet, unsigned char WIDE *in, unsigned char length,
                                unsigned char *out, unsigned char maxoutlen) {
    unsigned char tmp[164];
    unsigned char buffer[164];
    unsigned char j;
    unsigned char startAt;
    unsigned char zeroCount = 0;
    if (length > sizeof(tmp)) {
        THROW(INVALID_PARAMETER);
    }
    os_memmove(tmp, in, length);
    while ((zeroCount < length) && (tmp[zeroCount] == 0)) {
        ++zeroCount;
    }
    j = 2 * length;
    startAt = zeroCount;
    while (startAt < length) {
        unsigned short remainder = 0;
        unsigned char divLoop;
        for (divLoop = startAt; divLoop < length; divLoop++) {
            unsigned short digit256 = (unsigned short)(tmp[divLoop] & 0xff);
            unsigned short tmpDiv = remainder * 256 + digit256;
            tmp[divLoop] = (unsigned char)(tmpDiv / 58);
            remainder = (tmpDiv % 58);
        }
        if (tmp[startAt] == 0) {
            ++startAt;
        }
        buffer[--j] = (unsigned char)alphabet[remainder];
    }
    while ((j < (2 * length)) && (buffer[j] == alphabet[0])) {
        ++j;
    }
    while (zeroCount-- > 0) {
        buffer[--j] = alphabet[0];
    }
    length = 2 * length - j;
    if (maxoutlen < length) {
        THROW(EXCEPTION_OVERFLOW);
    }
    os_memmove(out, (buffer + j), length);
    return length;
}
