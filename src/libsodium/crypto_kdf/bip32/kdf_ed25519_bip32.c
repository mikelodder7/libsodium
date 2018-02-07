#include <errno.h>

#include "crypto_kdf_ed25519_bip32.h"
#include "private/common.h"

size_t crypto_kdf_ed25519_bip32_child_append_bytes(void)
{
    return crypto_kdf_ed25519_bip32_CHILD_APPEND_BYTES;
}

size_t crypto_kdf_ed25519_bip32_harden(void)
{
    return crypto_kdf_ed25519_bip32_HARDEN;
}
