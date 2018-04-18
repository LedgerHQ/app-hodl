#include "os.h"
#include "cx.h"

void getEthAddressStringFromKey(uint8_t *publicKey, uint8_t *out,
		                                cx_sha3_t *sha3Context);


void getEthAddressStringFromBinary(uint8_t *address, uint8_t *out,
		                                   cx_sha3_t *sha3Context);
