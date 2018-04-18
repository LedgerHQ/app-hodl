#include "os.h"
#include "cx.h"
#include "ethUtils.h"

static const uint8_t const HEXDIGITS[] = "0123456789abcdef";

void getEthAddressStringFromKey(uint8_t *publicKey, uint8_t *out,
                                cx_sha3_t *sha3Context) {
    uint8_t hashAddress[32];
    cx_keccak_init(sha3Context, 256);
    cx_hash((cx_hash_t *)sha3Context, CX_LAST, publicKey + 1, 64,
            hashAddress);
    getEthAddressStringFromBinary(hashAddress + 12, out, sha3Context);
}

void getEthAddressStringFromBinary(uint8_t *address, uint8_t *out,
                                   cx_sha3_t *sha3Context) {
    uint8_t hashChecksum[32];
    uint8_t tmp[40];
    uint8_t i;
    for (i = 0; i < 20; i++) {
        uint8_t digit = address[i];
        tmp[2 * i] = HEXDIGITS[(digit >> 4) & 0x0f];
        tmp[2 * i + 1] = HEXDIGITS[digit & 0x0f];
    }
    cx_keccak_init(sha3Context, 256);
    cx_hash((cx_hash_t *)sha3Context, CX_LAST, tmp, 40, hashChecksum);
    for (i = 0; i < 40; i++) {
        uint8_t hashDigit = hashChecksum[i / 2];
        if ((i % 2) == 0) {
            hashDigit = (hashDigit >> 4) & 0x0f;
        } else {
            hashDigit = hashDigit & 0x0f;
        }
        if ((hashDigit > 7) && (tmp[i] > '9')) {
            out[i] = tmp[i] - 'a' + 'A';
        } else {
            out[i] = tmp[i];
        }
    }
    out[40] = '\0';
}
