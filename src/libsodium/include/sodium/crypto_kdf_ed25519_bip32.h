#ifndef crypto_kdf_ed25519_bip32_H
#define crypto_kdf_ed25519_bip32_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_kdf_ed25519_bip32.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_kdf_ed25519_bip32_CHILD_APPEND_BYTES 28
SODIUM_EXPORT
size_t crypto_kdf_ed25519_bip32_child_append_bytes(void);

#define crypto_kdf_ed25519_bip32_HARDEN 0x8000000
SODIUM_EXPORT
size_t crypto_kdf_ed25519_bip32_harden(void);

SODIUM_EXPORT
int crypto_kdf_ed25519_bip32_clamp(unsigned char* const key, const size_t key_len);

SODIUM_EXPORT
int crypto_kdf_ed25519_bip32_set_bit(unsigned char* const key, const size_t key_len,
                                     uint32_t bit_pos, uint8_t value);

SODIUM_EXPORT
uint8_t crypto_kdf_ed25519_bip32_get_bit(const unsigned char* const key, const size_t key_len,
                                         uint32_t bit_pos);

SODIUM_EXPORT
int crypto_kdf_ed25519_bip32_pre_child_calc(unsigned char* addend, size_t* addend_len,
                                            unsigned char* child_chaincode, size_t* child_chaincode_len,
                                            unsigned char* z, size_t* z_len,
                                            uint32_t i,
                                            const unsigned char* chaincode, const size_t chaincode_len,
                                            const unsigned char* pubkey, const size_t pubkey_len,
                                            const unsigned char* ext_privkey, const size_t ext_privkey_len);

SODIUM_EXPORT
int crypto_kdf_ed25519_bip32_pre_child_calc_with_ext_priv_key(
                                    unsigned char* addend, size_t* addend_len,
                                    unsigned char* child_chaincode, size_t* child_chaincode_len,
                                    unsigned char* z, size_t* z_len,
                                    uint32_t i,
                                    const unsigned char* chaincode, const size_t chaincode_len,
                                    const unsigned char* pubkey, const size_t pubkey_len,
                                    const unsigned char* ext_privkey, const size_t ext_privkey_len);

SODIUM_EXPORT
int crypto_kdf_ed25519_bip32_root_keygen(unsigned char* a, size_t* a_len,
                                         unsigned char* sign_seed, size_t* sign_seed_len,
                                         unsigned char* chaincode, size_t* chaincode_len,
                                         unsigned char* pubkey, size_t* pubkey_len);

#ifdef __cplusplus
}
#endif

#endif
