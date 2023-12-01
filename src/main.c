/*******************************************************************************
*   Password Manager application
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

#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"

#include "ux.h"

#include "hid_mapping.h"
#include "base58.h"
#include "segwit_addr.h"
#include "cashaddr.h"
#include "crc16.h"
#include "base32.h"
#include "usbd_hid_impl.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define CLA 0xE0

bagl_element_t tmp_element;

ux_state_t ux;
// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

enum coin_type_e {
    COIN_TYPE_BITCOIN = 1,
    COIN_TYPE_BITCOIN_CASH = 2,
    COIN_TYPE_BITCOIN_GOLD = 3,
    COIN_TYPE_BITCOIN_PRIVATE = 4,
    COIN_TYPE_DASH = 5,
    COIN_TYPE_DIGIBYTE = 6,
    COIN_TYPE_DOGECOIN = 7,
    COIN_TYPE_HCASH = 8,
    COIN_TYPE_KOMODO = 9,
    COIN_TYPE_LITECOIN = 10,
    COIN_TYPE_PEERCOIN = 11,
    COIN_TYPE_PIVX = 12,
    COIN_TYPE_POSW = 13,
    COIN_TYPE_QTUM = 14,
    COIN_TYPE_STEALTHCOIN = 15,
    COIN_TYPE_STRATIS = 16,
    COIN_TYPE_VERTCOIN = 17,
    COIN_TYPE_VIACOIN = 18,
    COIN_TYPE_ZCASH = 19,
    COIN_TYPE_ZENCASH = 20,
    COIN_TYPE_ETHEREUM = 21,
    COIN_TYPE_ETHEREUM_CLASSIC = 22,
    COIN_TYPE_RIPPLE = 23,    
    COIN_TYPE_STELLAR = 24,
    COIN_TYPE_NEO = 25,
    COIN_TYPE_ARK = 26,
//    COIN_TYPE_NANO = 27,
//    COIN_TYPE_NIMIQ = 28,
    COIN_TYPE_ZCOIN = 29,
    COIN_TYPE_TRON = 30
    
};
typedef enum coin_type_e coin_type_t;

enum address_encoding_e {
    ADDRESS_ENCODING_LEGACY = 1,
    ADDRESS_ENCODING_SEGWIT = 2,
    ADDRESS_ENCODING_BECH32 = 3,
    ADDRESS_ENCODING_CASHADDR = 4
};
typedef enum address_encoding_e address_encoding_t;

typedef struct internalStorage_t {
#define STORAGE_MAGIC 0xDEAD1337
    uint32_t magic;
    uint32_t keyboard_layout;
} internalStorage_t;

WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))

uint8_t write_metadata(uint8_t *data, uint8_t dataSize);

static const uint8_t EMPTY_REPORT[] = {0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00};
static const uint8_t SPACE_REPORT[] = {0x00, 0x00, 0x2C, 0x00,
                                       0x00, 0x00, 0x00, 0x00};
static const uint8_t CAPS_REPORT[] = {0x02, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00};
static const uint8_t CAPS_LOCK_REPORT[] = {0x00, 0x00, 0x39, 0x00,
                                           0x00, 0x00, 0x00, 0x00};

volatile unsigned int G_led_status;

coin_type_t coinType;
address_encoding_t addressEncoding;
uint32_t derivePurpose;
uint32_t coinIndex;
uint32_t coinAccount;
uint8_t hrp[20];

#if CX_APILEVEL < 10
extern struct {
  unsigned short timeout; // up to 64k milliseconds (6 sec)
} G_io_usb_ep_timeouts[IO_USB_MAX_ENDPOINTS];
#endif
void io_usb_send_ep_wait(unsigned int ep, unsigned char* buf, unsigned int len, unsigned int timeout_cs) {
    io_usb_send_ep(ep, buf, len, 20);

    // wait until transfer timeout, or ended
#if CX_APILEVEL < 10
    while (G_io_usb_ep_timeouts[ep&0x7F].timeout) {
#else
    while (G_io_app.usb_ep_timeouts[ep&0x7F].timeout) {	   
#endif	  
        if (!io_seproxyhal_spi_is_status_sent()) {
            io_seproxyhal_general_status();
        }
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();
    }
}

void type_address(char *address) {
    uint8_t i;
    uint32_t led_status;
    uint8_t report[8];
    uint8_t len = strlen(address);

    os_memset(report, 0, sizeof(report));
    // Insert EMPTY_REPORT CAPS_REPORT EMPTY_REPORT to avoid undesired capital
    // letter on KONSOLE
    led_status = G_led_status;
    io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);
    io_usb_send_ep_wait(HID_EPIN_ADDR, CAPS_REPORT, 8, 20);
    io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);

    // toggle shift if set.
    if (led_status & 2) {
        io_usb_send_ep_wait(HID_EPIN_ADDR, CAPS_LOCK_REPORT, 8, 20);
        io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);
    }
    for (i = 0; i < len; i++) {
        // If keyboard layout not initialized, use the default
        map_char(N_storage.keyboard_layout, address[i], report);
        io_usb_send_ep_wait(HID_EPIN_ADDR, report, 8, 20);
        io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);

        if (N_storage.keyboard_layout == HID_MAPPING_QWERTY_INTL) {
            switch (address[i]) {
            case '\"':
            case '\'':
            case '`':
            case '~':
            case '^':
                // insert a extra space to validate the symbol
                io_usb_send_ep_wait(HID_EPIN_ADDR, SPACE_REPORT, 8, 20);
                io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);
                break;
            }
        }
    }
    // restore shift state
    if (led_status & 2) {
        io_usb_send_ep_wait(HID_EPIN_ADDR, CAPS_LOCK_REPORT, 8, 20);
        io_usb_send_ep_wait(HID_EPIN_ADDR, EMPTY_REPORT, 8, 20);
    }
}

#if defined(TARGET_NANOS)

const bagl_element_t*  menu_accounts_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element);
const bagl_element_t*  menu_accounts_noindex_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element);
unsigned int ui_display_address_nanos_prepro(const bagl_element_t* element);
unsigned int ui_display_address_nanos_button(unsigned int button_mask, unsigned int button_mask_counter);

const ux_menu_entry_t menu_main[];
const ux_menu_entry_t menu_settings[];
const ux_menu_entry_t menu_about[];
const ux_menu_entry_t menu_coins[];
const ux_menu_entry_t menu_accounts[];
const ux_menu_entry_t menu_accounts_noindex[];
const ux_menu_entry_t menu_address_encoding_btc_segwit[];
const ux_menu_entry_t menu_address_encoding_btc_segwit_bech32[];
const ux_menu_entry_t menu_address_encoding_bch[];
char accountInfo[50];

const bagl_element_t ui_display_address_nanos[] = {
  // type                               userid    x    y   w    h  str rad fill      fg        bg      fid iid  txt   touchparams...       ]
  {{BAGL_RECTANGLE                      , 0x00,   0,   0, 128,  32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_ICON                           , 0x00,   3,  12,   7,   7, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS  }, NULL, 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_ICON                           , 0x00, 117,  13,   8,   6, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK  }, NULL, 0, 0, 0, NULL, NULL, NULL },

  //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0, 0, NULL, NULL, NULL },  
  {{BAGL_LABELINE                       , 0x01,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Confirm", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x01,   0,  26, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "address", 0, 0, 0, NULL, NULL, NULL },

  {{BAGL_LABELINE                       , 0x02,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Address", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x02,  23,  26,  82,  12, 0x80|10, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 26  },  G_io_apdu_buffer, 0, 0, 0, NULL, NULL, NULL },


  //{{BAGL_ICON                           , 0x00,   1,  1,   32,  32, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, 0 }, &vars.tmpqr.icon_details, 0, 0, 0, NULL, NULL, NULL },
};

// change the setting
void menu_settings_layout_change(uint32_t layout) {
    nvm_write(&N_storage.keyboard_layout, (void *)&layout, sizeof(uint32_t));
    // go back to the menu entry
    UX_MENU_DISPLAY(0, menu_settings, NULL);
}

const ux_menu_entry_t menu_settings_layout[] = {
    {NULL, menu_settings_layout_change, HID_MAPPING_QWERTY, NULL, "Qwerty",
     NULL, 0, 0},
    {NULL, menu_settings_layout_change, HID_MAPPING_QWERTY_INTL, NULL,
     "Qwerty Int'l", NULL, 0, 0},
    {NULL, menu_settings_layout_change, HID_MAPPING_AZERTY, NULL, "Azerty",
     NULL, 0, 0},
    //  {NULL, menu_settings_layout_change, 3, NULL, "Qwertz", NULL, 0, 0},
    UX_MENU_END};

// show the currently activated entry
void menu_settings_layout_init(unsigned int ignored) {
    UNUSED(ignored);
    UX_MENU_DISPLAY(
        N_storage.keyboard_layout > 0 ? N_storage.keyboard_layout - 1 : 0,
        menu_settings_layout, NULL);
}

void menu_encoding_selected_btc(uint32_t encoding) {
    addressEncoding = encoding;
    switch(encoding) {
        case ADDRESS_ENCODING_SEGWIT:
            derivePurpose = 0x80000031;
            break;
        case ADDRESS_ENCODING_BECH32:
            derivePurpose = 0x80000054;
            switch(coinType) {
                case COIN_TYPE_BITCOIN:
                    strcpy(hrp, "bc");
                    break;
                case COIN_TYPE_VERTCOIN:
                    strcpy(hrp, "vtc");
                    break;
                case COIN_TYPE_VIACOIN:
                    strcpy(hrp, "via");
                    break;
            }
            break;
    }
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}

void menu_encoding_selected_bch(uint32_t encoding) {
    addressEncoding = encoding;
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}

void menu_coin_selected(uint32_t coin) {
    coinType = coin;
    addressEncoding = ADDRESS_ENCODING_LEGACY;
    derivePurpose = 0x8000002C;
    coinIndex = 0;
    coinAccount = 0;
    switch(coinType) {
        case COIN_TYPE_BITCOIN:
        case COIN_TYPE_VERTCOIN:
        case COIN_TYPE_VIACOIN:
            UX_MENU_DISPLAY(0, menu_address_encoding_btc_segwit_bech32, NULL);
            break;
        case COIN_TYPE_BITCOIN_GOLD:
        case COIN_TYPE_DIGIBYTE:
        case COIN_TYPE_LITECOIN:        
            UX_MENU_DISPLAY(0, menu_address_encoding_btc_segwit, NULL);
            break;        
        case COIN_TYPE_BITCOIN_CASH:
            UX_MENU_DISPLAY(0, menu_address_encoding_bch, NULL);
            break;         
        case COIN_TYPE_BITCOIN_PRIVATE:
        case COIN_TYPE_DASH:
        case COIN_TYPE_DOGECOIN:
        case COIN_TYPE_HCASH:
        case COIN_TYPE_KOMODO:
        case COIN_TYPE_PEERCOIN:
        case COIN_TYPE_PIVX:
        case COIN_TYPE_POSW:
        case COIN_TYPE_QTUM:
        case COIN_TYPE_STEALTHCOIN:
        case COIN_TYPE_STRATIS:
        case COIN_TYPE_ZCASH:
        case COIN_TYPE_ZENCASH:
        case COIN_TYPE_ETHEREUM:
        case COIN_TYPE_ETHEREUM_CLASSIC:
        case COIN_TYPE_RIPPLE:        
        case COIN_TYPE_NEO:
        case COIN_TYPE_ARK:   
//        case COIN_TYPE_NANO:
        case COIN_TYPE_ZCOIN:
        case COIN_TYPE_TRON:  
            UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
            break;
        case COIN_TYPE_STELLAR:
//        case COIN_TYPE_NIMIQ:
            UX_MENU_DISPLAY(0, menu_accounts_noindex, menu_accounts_noindex_preprocessor);
            break;        
        default:
            UX_MENU_DISPLAY(0, menu_main, NULL);
            break;
    }
}

const bagl_element_t*  menu_accounts_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {
 if(element->component.userid==0x20) {
    if (entry == &menu_accounts[0]) {
        switch(coinType) {
            case COIN_TYPE_BITCOIN:
                //element->icon = &C_nanos_badge_bitcoin;
                break;
            case COIN_TYPE_RIPPLE:
                //element->icon = &C_icon_ripple;
                break;                
        }
        snprintf(accountInfo, sizeof(accountInfo), "/%d/%d", coinAccount, coinIndex);
        //element->line1 = accountInfo;
        element->text = accountInfo;
    }
 }
 return element;
}

const bagl_element_t*  menu_accounts_noindex_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {
 if(element->component.userid==0x20) {
    if (entry == &menu_accounts_noindex[0]) {
        switch(coinType) {
            case COIN_TYPE_BITCOIN:
                //element->icon = &C_nanos_badge_bitcoin;
                break;
            case COIN_TYPE_RIPPLE:
                //element->icon = &C_icon_ripple;
                break;                
        }
        snprintf(accountInfo, sizeof(accountInfo), "/%d", coinAccount);
        //element->line1 = accountInfo;
        element->text = accountInfo;
    }
 }
 return element;
}


void compress_ecdsa(uint8_t *publicAddress) {
    publicAddress[0] = ((publicAddress[64] & 1) ? 0x03 : 0x02);    
}

void handle_btc_address(uint8_t *publicAddress) {
    uint32_t version;
    uint8_t tmpBuffer[26];
    uint8_t checksumBuffer[32];
    uint8_t scriptAddress[22];
    uint8_t versionSize;
    uint32_t addressLength;
    uint8_t *alphabet;
    union {
        cx_sha256_t sha;
        cx_ripemd160_t rip;
    } u;
    compress_ecdsa(publicAddress);
    if (coinType == COIN_TYPE_RIPPLE) {
        alphabet = N_XRP_BASE58_ALPHABET;
    }
    else {
        alphabet = N_BTC_BASE58_ALPHABET;
    }
    switch(coinType) {
        case COIN_TYPE_BITCOIN:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 5 : 0);
            break;
        case COIN_TYPE_BITCOIN_GOLD:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 38 : 23);
            break;        
        case COIN_TYPE_BITCOIN_PRIVATE:
            version = 4901;
            break;                
        case COIN_TYPE_DASH:
            version = 76;
            break;
        case COIN_TYPE_DIGIBYTE:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 5 : 30);
            break;
        case COIN_TYPE_DOGECOIN:
            version = 30;
            break;
        case COIN_TYPE_HCASH:
            version = 40;
            break;
        case COIN_TYPE_KOMODO:
            version = 60;
            break;
        case COIN_TYPE_LITECOIN:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 50 : 48);
            break;
        case COIN_TYPE_PEERCOIN:
            version = 55;
            break;
        case COIN_TYPE_PIVX:
            version = 30;
            break;
        case COIN_TYPE_POSW:
            version = 55;
            break;
        case COIN_TYPE_QTUM:
            version = 58;
            break;
        case COIN_TYPE_STEALTHCOIN:
            version = 62;
            break;
        case COIN_TYPE_STRATIS:
            version = 63;
            break;
        case COIN_TYPE_VERTCOIN:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 5 : 71);
            break;
        case COIN_TYPE_VIACOIN:
            version = (addressEncoding == ADDRESS_ENCODING_SEGWIT ? 33 : 71);
            break;
        case COIN_TYPE_ZCASH:
            version = 7352;
            break;
        case COIN_TYPE_ZENCASH:
            version = 8329;
            break;
        case COIN_TYPE_ZCOIN:
            version = 82;
            break;
        case COIN_TYPE_BITCOIN_CASH:
            version = 0;
            break;
        case COIN_TYPE_RIPPLE:
            version = 0;
            break;
        case COIN_TYPE_ARK:
            version = 23;
            break;
        default:
            THROW(EXCEPTION);
    } 
    switch(addressEncoding) {
        case ADDRESS_ENCODING_SEGWIT:
        case ADDRESS_ENCODING_BECH32:
        case ADDRESS_ENCODING_CASHADDR:
            scriptAddress[0] = 0x00;
            scriptAddress[1] = 0x14;
            cx_sha256_init(&u.sha);
            cx_hash(&u.sha.header, CX_LAST, publicAddress, 33, checksumBuffer, sizeof(checksumBuffer));
            cx_ripemd160_init(&u.rip);
            cx_hash(&u.rip.header, CX_LAST, checksumBuffer, 32, scriptAddress + 2, sizeof(scriptAddress) - 2);
            break;
        case ADDRESS_ENCODING_LEGACY:
            break;
        default:
            THROW(EXCEPTION);            
    }
    switch(addressEncoding) {
        case ADDRESS_ENCODING_LEGACY:
        case ADDRESS_ENCODING_SEGWIT: {
            uint8_t *addressData;
            uint8_t addressLength;
            if (addressEncoding == ADDRESS_ENCODING_SEGWIT) {                                
                addressData = scriptAddress;
                addressLength = 22;
            }
            else {
                addressData = publicAddress;
                addressLength = 33;
            }
            if (version > 255) {
                tmpBuffer[0] = (version >> 8);
                tmpBuffer[1] = version;
                versionSize = 2;
            }
            else {
                tmpBuffer[0] = version;
                versionSize = 1;
            }
            switch(coinType) {
                case COIN_TYPE_ARK:
                    cx_ripemd160_init(&u.rip);
                    cx_hash(&u.rip.header, CX_LAST, addressData, addressLength, tmpBuffer + versionSize, 20);
                    break;
                default:
                    cx_sha256_init(&u.sha);
                    cx_hash(&u.sha.header, CX_LAST, addressData, addressLength, checksumBuffer, sizeof(checksumBuffer));
                    cx_ripemd160_init(&u.rip);
                    cx_hash(&u.rip.header, CX_LAST, checksumBuffer, 32, tmpBuffer + versionSize, 20);
                    break;
            }
            cx_sha256_init(&u.sha);
            cx_hash(&u.sha.header, CX_LAST, tmpBuffer, 20 + versionSize, checksumBuffer, sizeof(checksumBuffer));
            cx_sha256_init(&u.sha);
            cx_hash(&u.sha.header, CX_LAST, checksumBuffer, 32, checksumBuffer, sizeof(checksumBuffer));
            os_memmove(tmpBuffer + 20 + versionSize, checksumBuffer, 4);
            addressLength = hodl_encode_base58(alphabet, tmpBuffer, 24 + versionSize, G_io_apdu_buffer, 255);
            G_io_apdu_buffer[addressLength] = '\0';
            break;
        }
        case ADDRESS_ENCODING_BECH32:
            segwit_addr_encode(G_io_apdu_buffer, hrp, 0, scriptAddress + 2, 20);
            break;
        case ADDRESS_ENCODING_CASHADDR:
            cashaddr_encode(scriptAddress + 2, 20, G_io_apdu_buffer, 255, CASHADDR_P2PKH);
            break;
    }    
}

void handle_tron_address(uint8_t *publicAddress) {
    union {
        cx_sha3_t sha3;
        cx_sha256_t sha2;
    } u;
    uint8_t hash[32];
    uint8_t address[25];
    cx_keccak_init(&u.sha3, 256);
    cx_hash((cx_hash_t *)&u.sha3, CX_LAST, publicAddress + 1, 64, hash, sizeof(hash));
    os_memmove(address, hash + 11, 21);
    address[0] = 0x41;
    uint8_t checkSum[4];
    uint32_t addressLength;
    cx_sha256_init(&u.sha2);
    cx_hash(&u.sha2, CX_LAST, address, 21, hash, sizeof(hash));
    cx_sha256_init(&u.sha2);
    cx_hash(&u.sha2, CX_LAST, hash, 32, hash, sizeof(hash));
    os_memmove(address+21, hash, 4);
    addressLength = hodl_encode_base58(N_BTC_BASE58_ALPHABET, address, 25, G_io_apdu_buffer, 255);
    G_io_apdu_buffer[addressLength] = '\0';
}

void handle_neo_address(uint8_t *publicAddress) {
    union {
        cx_sha256_t sha;
        cx_ripemd160_t rip;
    } u;
    uint8_t tmpBuffer[35];
    uint8_t checksumBuffer[32];
    uint8_t addressBuffer[1 + 20 + 4];
    uint32_t addressLength;
    compress_ecdsa(publicAddress);
    addressBuffer[0] = 0x17;    
    tmpBuffer[0] = 0x21;
    os_memmove(tmpBuffer + 1, publicAddress, 33);
    tmpBuffer[34] = 0xac;
    cx_sha256_init(&u.sha);
    cx_hash(&u.sha.header, CX_LAST, tmpBuffer, 35, checksumBuffer, sizeof(checksumBuffer));
    cx_ripemd160_init(&u.rip);    
    cx_hash(&u.rip.header, CX_LAST, checksumBuffer, 32, addressBuffer + 1, 20);
    checksumBuffer[0] = 0x17;
    os_memmove(checksumBuffer + 1, addressBuffer + 1, 20);
    cx_sha256_init(&u.sha);
    cx_hash(&u.sha.header, CX_LAST, checksumBuffer, 21, checksumBuffer, sizeof(checksumBuffer));
    cx_sha256_init(&u.sha);
    cx_hash(&u.sha.header, CX_LAST, checksumBuffer, 32, checksumBuffer, sizeof(checksumBuffer));
    os_memmove(addressBuffer + 1 + 20, checksumBuffer, 4);
    addressLength = hodl_encode_base58(N_BTC_BASE58_ALPHABET, addressBuffer, 25, G_io_apdu_buffer, 255);
    G_io_apdu_buffer[addressLength] = '\0';
}

void handle_stellar_address(uint8_t *publicAddress) {
    uint8_t buffer[35];
    uint8_t publicKey[32];
    uint8_t i;
    for (i = 0; i < 32; i++) {
        publicKey[i] = publicAddress[64 - i];
    }
    if ((publicAddress[32] & 1) != 0) {
        publicKey[31] |= 0x80;
    }        
    buffer[0] = 6 << 3; // version bit 'G'
    for (i = 0; i < 32; i++) {
        buffer[i+1] = publicKey[i];
    }
    short crc = crc16((char *)buffer, 33); // checksum
    buffer[33] = crc;
    buffer[34] = crc >> 8;
    base32_encode(buffer, 35, G_io_apdu_buffer, 56);
    G_io_apdu_buffer[56] = '\0';
}

void handle_eth_address(uint8_t *publicAddress) {
    cx_sha3_t sha3;
    getEthAddressStringFromKey(publicAddress, G_io_apdu_buffer, &sha3);
}

void menu_generate(uint32_t dummy) {
    UNUSED(dummy);
    uint32_t derivePath[5];
    uint8_t privateComponent[32];
    uint32_t curve = CX_CURVE_256K1;
    uint8_t derivePathLength;
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;

    derivePath[0] = derivePurpose;
    switch(coinType) {
        case COIN_TYPE_NEO:
            curve = CX_CURVE_256R1;
            break;
        case COIN_TYPE_STELLAR:
//        case COIN_TYPE_NIMIQ:
            curve = CX_CURVE_Ed25519;
            break;
/*        case COIN_TYPE_NANO:
            curve = CX_CURVE_Ed25519;
            break;*/
    }
    switch(coinType) {
        case COIN_TYPE_BITCOIN:        
            derivePath[1] = 0x80000000;
            break;
        case COIN_TYPE_BITCOIN_GOLD:
            derivePath[1] = 0x8000009c;
            break;            
        case COIN_TYPE_BITCOIN_PRIVATE:
            derivePath[1] = 0x800000b7;
            break;
        case COIN_TYPE_BITCOIN_CASH:
            derivePath[1] = 0x80000091;
            break;

        case COIN_TYPE_DIGIBYTE:
            derivePath[1] = 0x80000014;
            break;
        case COIN_TYPE_DASH:
            derivePath[1] = 0x80000005;
            break;
        case COIN_TYPE_DOGECOIN:
            derivePath[1] = 0x80000003;
            break;
        case COIN_TYPE_ETHEREUM:
            derivePath[1] = 0x8000003c;
            break;
        case COIN_TYPE_ETHEREUM_CLASSIC:
            derivePath[1] = 0x8000003d;
            break;            
        case COIN_TYPE_HCASH:
            derivePath[1] = 0x800000ab;
            break;
        case COIN_TYPE_KOMODO:
            derivePath[1] = 0x8000008d;
            break;
        case COIN_TYPE_LITECOIN:
            derivePath[1] = 0x80000002;
            break;
        case COIN_TYPE_PEERCOIN:
            derivePath[1] = 0x80000006;
            break;        
        case COIN_TYPE_PIVX:
            derivePath[1] = 0x80000077;
            break;
        case COIN_TYPE_POSW:
            derivePath[1] = 0x8000002f;
            break;
        case COIN_TYPE_QTUM:
            derivePath[1] = 0x800008fd;
            break;
        case COIN_TYPE_STEALTHCOIN:
            derivePath[1] = 0x8000007d;
            break;
        case COIN_TYPE_STRATIS:
            derivePath[1] = 0x80000069;
            break;
        case COIN_TYPE_VERTCOIN:
            derivePath[1] = 0x80000080;
            break;
        case COIN_TYPE_VIACOIN:
            derivePath[1] = 0x8000000e;
            break;
        case COIN_TYPE_ZCASH:
            derivePath[1] = 0x80000085;
            break;
        case COIN_TYPE_ZENCASH:
            derivePath[1] = 0x80000079;
            break;            
        case COIN_TYPE_RIPPLE:
            derivePath[1] = 0x80000090;
            break;
        case COIN_TYPE_STELLAR:
            derivePath[1] = 0x80000094;
            break;            
        case COIN_TYPE_NEO:
            derivePath[1] = 0x80000378;
            break;
        case COIN_TYPE_ARK:
            derivePath[1] = 0x8000006f;
            break;
/*        case COIN_TYPE_NANO:
            derivePath[1] = 0x800000a5;
            break;
        case COIN_TYPE_NIMIQ:
            derivePath[1] = 0x800000f2;
            break;*/
        case COIN_TYPE_ZCOIN:
            derivePath[1] = 0x80000088;
            break;
        case COIN_TYPE_TRON:
            derivePath[1] = 0x800000c3;
            break;
    }

    derivePath[2] = 0x80000000 | coinAccount;
    switch(coinType) {
        case COIN_TYPE_STELLAR:
//        case COIN_TYPE_NIMIQ:
            derivePathLength = 3;
            break;
        default:            
            derivePath[3] = 0;
            derivePath[4] = coinIndex;
            derivePathLength = 5;            
            break;
    }

    switch (curve)
    {
        case CX_CURVE_Ed25519:
            switch (coinType)
            {
                case COIN_TYPE_STELLAR:
                    os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, curve, derivePath, derivePathLength, privateComponent, NULL, NULL, 0);
                    break;
            
                default:
                    THROW(EXCEPTION);
                    break;
            }
            break;
    
        case CX_CURVE_256R1:
        case CX_CURVE_256K1:
            os_perso_derive_node_bip32(curve, derivePath, derivePathLength, privateComponent, NULL);
            break;

        default:
            THROW(EXCEPTION);
            break;
    }

    cx_ecdsa_init_private_key(curve, privateComponent, 32, &privateKey);
    os_memset(privateComponent, 0, 32);
    cx_ecdsa_init_public_key(curve, NULL, 0, &publicKey);
    cx_ecfp_generate_pair(curve, &publicKey, &privateKey, 1);
    os_memset(&privateKey, 0, sizeof(cx_ecfp_private_key_t));

    switch(coinType) {
        case COIN_TYPE_BITCOIN:
        case COIN_TYPE_RIPPLE:
        case COIN_TYPE_BITCOIN_CASH:
        case COIN_TYPE_BITCOIN_GOLD:
        case COIN_TYPE_BITCOIN_PRIVATE:
        case COIN_TYPE_DASH:
        case COIN_TYPE_DIGIBYTE:
        case COIN_TYPE_DOGECOIN:
        case COIN_TYPE_HCASH:
        case COIN_TYPE_KOMODO:
        case COIN_TYPE_LITECOIN:
        case COIN_TYPE_PEERCOIN:
        case COIN_TYPE_PIVX:
        case COIN_TYPE_POSW:
        case COIN_TYPE_QTUM:
        case COIN_TYPE_STEALTHCOIN:
        case COIN_TYPE_STRATIS:
        case COIN_TYPE_VERTCOIN:
        case COIN_TYPE_VIACOIN:
        case COIN_TYPE_ZCASH:
        case COIN_TYPE_ZENCASH:
        case COIN_TYPE_ARK:
        case COIN_TYPE_ZCOIN:
            handle_btc_address(publicKey.W);
            break;
        case COIN_TYPE_ETHEREUM:
        case COIN_TYPE_ETHEREUM_CLASSIC:
            handle_eth_address(publicKey.W);
            break;
        case COIN_TYPE_STELLAR:
//        case COIN_TYPE_NIMIQ:
            handle_stellar_address(publicKey.W);
            break;
        case COIN_TYPE_NEO:
            handle_neo_address(publicKey.W);
            break;
        case COIN_TYPE_TRON:
            handle_tron_address(publicKey.W);
            break;
        default:
            THROW(EXCEPTION);
    }    

    type_address(G_io_apdu_buffer);

    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_display_address_nanos, ui_display_address_nanos_prepro);
}

void menu_index_next(uint32_t dummy) {
    UNUSED(dummy);
    coinIndex++;
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}

void menu_index_previous(uint32_t dummy) {
    UNUSED(dummy);
    if (coinIndex != 0) {
        coinIndex--;
    }
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}    

void menu_account_next(uint32_t dummy) {
    UNUSED(dummy);
    coinAccount++;
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}

void menu_account_previous(uint32_t dummy) {
    UNUSED(dummy);
    if (coinAccount != 0) {
        coinAccount--;
    }
    UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
}    

void menu_account_noindex_next(uint32_t dummy) {
    UNUSED(dummy);
    coinAccount++;
    UX_MENU_DISPLAY(0, menu_accounts_noindex, menu_accounts_noindex_preprocessor);
}

void menu_account_noindex_previous(uint32_t dummy) {
    UNUSED(dummy);
    if (coinAccount != 0) {
        coinAccount--;
    }
    UX_MENU_DISPLAY(0, menu_accounts_noindex, menu_accounts_noindex_preprocessor);
}    
    
const ux_menu_entry_t menu_settings[] = {
    {NULL, menu_settings_layout_init, 0, NULL, "Keyboard layout", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_coins[] = {
    { NULL, menu_coin_selected, COIN_TYPE_ARK, &C_icon_ark, "Ark", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_BITCOIN, &C_nanos_badge_bitcoin, "Bitcoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_BITCOIN_CASH, &C_nanos_badge_bitcoin, "Bitcoin", "Cash", 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_BITCOIN_GOLD, &C_nanos_badge_bitcoin, "Bitcoin", "Gold", 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_BITCOIN_PRIVATE, &C_nanos_badge_bitcoin_private, "Bitcoin", "Private", 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_DASH, &C_nanos_badge_dash, "Dash", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_DIGIBYTE, &C_nanos_badge_digibyte, "Digibyte", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_DOGECOIN, &C_nanos_badge_dogecoin, "Dogecoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_ETHEREUM, &C_nanos_badge_ethereum, "Ethereum", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_ETHEREUM_CLASSIC, &C_nanos_badge_ethereum, "Ethereum", "Classic", 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_HCASH, &C_nanos_badge_hcash, "Hcash", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_KOMODO, &C_nanos_badge_komodo, "Komodo", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_LITECOIN, &C_nanos_badge_litecoin, "Litecoin", NULL, 50, 29},
    //    { NULL, menu_coin_selected, COIN_TYPE_NANO, &C_icon_nano, "Nano", NULL, 50, 29},        
    { NULL, menu_coin_selected, COIN_TYPE_NEO, &C_icon_neo, "Neo", NULL, 50, 29},        
//    { NULL, menu_coin_selected, COIN_TYPE_NIMIQ, &C_icon_nimiq, "Nimiq", NULL, 50, 29},        
    { NULL, menu_coin_selected, COIN_TYPE_PEERCOIN, &C_nanos_badge_peercoin, "Peercoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_PIVX, &C_nanos_badge_pivx, "PivX", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_POSW, &C_nanos_badge_posw, "PoSW", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_QTUM, &C_nanos_badge_qtum, "Qtum", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_RIPPLE, &C_icon_ripple, "Ripple", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_STEALTHCOIN, &C_nanos_badge_stealthcoin, "Stealthcoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_STELLAR, &C_icon_stellar, "Stellar", NULL, 50, 29},    
    { NULL, menu_coin_selected, COIN_TYPE_STRATIS, &C_nanos_badge_stratis, "Stratis", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_TRON, &C_nanos_badge_tron, "Tron", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_VERTCOIN, &C_nanos_badge_vertcoin, "Vertcoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_VIACOIN, &C_nanos_badge_viacoin, "Viacoin", NULL, 50, 29},    
    { NULL, menu_coin_selected, COIN_TYPE_ZCASH, &C_nanos_badge_zcash, "Zcash", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_ZCOIN, &C_nanos_badge_zcoin, "Zcoin", NULL, 50, 29},
    { NULL, menu_coin_selected, COIN_TYPE_ZENCASH, &C_nanos_badge_zencash, "ZenCash", NULL, 50, 29},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_address_encoding_btc_segwit_bech32[] = {
    { NULL, menu_encoding_selected_btc, ADDRESS_ENCODING_LEGACY, NULL, "Legacy", NULL, 0, 0},
    { NULL, menu_encoding_selected_btc, ADDRESS_ENCODING_SEGWIT, NULL, "Segwit", NULL, 0, 0},
    { NULL, menu_encoding_selected_btc, ADDRESS_ENCODING_BECH32, NULL, "Bech32", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_address_encoding_btc_segwit[] = {
    { NULL, menu_encoding_selected_btc, ADDRESS_ENCODING_LEGACY, NULL, "Legacy", NULL, 0, 0},
    { NULL, menu_encoding_selected_btc, ADDRESS_ENCODING_SEGWIT, NULL, "Segwit", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_address_encoding_bch[] = {
    { NULL, menu_encoding_selected_bch, ADDRESS_ENCODING_LEGACY, NULL, "Legacy", NULL, 0, 0},
    { NULL, menu_encoding_selected_bch, ADDRESS_ENCODING_CASHADDR, NULL, "Cashaddr", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};


const ux_menu_entry_t menu_accounts[] = {
    { NULL, NULL, 0, NULL, "test", NULL, 0, 0 },
    { NULL, menu_generate, 0, NULL, "Generate", NULL, 0, 0},
    { NULL, menu_index_next, 0, NULL, "Next index", NULL, 0, 0},
    { NULL, menu_index_previous, 0, NULL, "Previous index", NULL, 0, 0},
    { NULL, menu_account_next, 0, NULL, "Next account", NULL, 0, 0},
    { NULL, menu_account_previous, 0, NULL, "Previous account", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_accounts_noindex[] = {
    { NULL, NULL, 0, NULL, "test", NULL, 0, 0 },
    { NULL, menu_generate, 0, NULL, "Generate", NULL, 0, 0},
    { NULL, menu_account_noindex_next, 0, NULL, "Next account", NULL, 0, 0},
    { NULL, menu_account_noindex_previous, 0, NULL, "Previous account", NULL, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {menu_coins, NULL, 0, NULL, "New address", NULL, 0, 0},
    {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};


unsigned int ui_display_address_nanos_prepro(const bagl_element_t* element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid-1);
        if(display) {
          switch(element->component.userid) {
          case 1:
            UX_CALLBACK_SET_INTERVAL(2000);
            break;
          case 2:
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000+bagl_label_roundtrip_duration_ms(element, 7)));
            break;
          }
        }
        return display;
    }
    return 1;
}

unsigned int ui_display_address_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
    switch(coinType) {
        case COIN_TYPE_STELLAR:
//        case COIN_TYPE_NIMIQ:
            UX_MENU_DISPLAY(0, menu_accounts_noindex, menu_accounts_noindex_preprocessor);
            break;
        default:
            UX_MENU_DISPLAY(0, menu_accounts, menu_accounts_preprocessor);
            break;
    }    
    return 1;
}

#endif // #if defined(TARGET_NANOS)

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {
                }
                // default no error
                THROW(0x9000);
            }
            CATCH_OTHER(e) {
                switch (e & 0xFFFFF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    // TODO here: error processing, memory wipes ?
                    break;
                case 0x9000:
                    // ok
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({
        });
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // a pin lock is undergoing ?
            if (UX_ALLOWED) {
                if (ux_step_count) {
                    // prepare next screen
                    ux_step = (ux_step + 1) % ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                }
                break;
            }
        });
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            if (N_storage.magic != STORAGE_MAGIC) {
                uint32_t magic;
                magic = STORAGE_MAGIC;
                nvm_write(&N_storage.magic, (void *)&magic, sizeof(uint32_t));
            }

            USB_power(1);

            UX_MENU_DISPLAY(0, menu_main, NULL);

            sample_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();

    return 0;
}
