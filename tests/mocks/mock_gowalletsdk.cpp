// Mock implementation of the Go Wallet SDK C library (libgowalletsdk).
// Replaces the real static library at link time during testing.
// Function names and signatures match those called by accounts_module_impl.cpp.

#include <logos_clib_mock.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>

extern "C" {

typedef unsigned long long GoWSKHandle;

void GoWSK_FreeCString(char* str) {
    LOGOS_CMOCK_RECORD("GoWSK_FreeCString");
    if (str) free(str);
}

// ── Keystore ────────────────────────────────────────────────────────────────

GoWSKHandle GoWSK_accounts_keystore_NewKeyStore(
    const char* dir, int scryptN, int scryptP, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_NewKeyStore");
    if (error) *error = nullptr;
    return static_cast<GoWSKHandle>(
        LogosCMockStore::instance().getReturn<int>("GoWSK_accounts_keystore_NewKeyStore"));
}

void GoWSK_accounts_keystore_CloseKeyStore(GoWSKHandle handle) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_CloseKeyStore");
    (void)handle;
}

char* GoWSK_accounts_keystore_Accounts(GoWSKHandle handle, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Accounts");
    (void)handle;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_Accounts");
    return strdup(ret ? ret : "[]");
}

char* GoWSK_accounts_keystore_NewAccount(GoWSKHandle handle, const char* passphrase, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_NewAccount");
    (void)handle; (void)passphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_NewAccount");
    return strdup(ret ? ret : "0x0000");
}

char* GoWSK_accounts_keystore_Import(
    GoWSKHandle handle, const char* keyJSON, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Import");
    (void)handle; (void)keyJSON; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_Import");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_Export(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Export");
    (void)handle; (void)address; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_Export");
    return strdup(ret ? ret : "{}");
}

void GoWSK_accounts_keystore_Delete(
    GoWSKHandle handle, const char* address, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Delete");
    (void)handle; (void)address; (void)passphrase;
    if (error) *error = nullptr;
}

int GoWSK_accounts_keystore_HasAddress(GoWSKHandle handle, const char* address, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_HasAddress");
    (void)handle; (void)address;
    if (error) *error = nullptr;
    return LOGOS_CMOCK_RETURN(int, "GoWSK_accounts_keystore_HasAddress");
}

void GoWSK_accounts_keystore_Unlock(
    GoWSKHandle handle, const char* address, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Unlock");
    (void)handle; (void)address; (void)passphrase;
    if (error) *error = nullptr;
}

void GoWSK_accounts_keystore_Lock(GoWSKHandle handle, const char* address, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Lock");
    (void)handle; (void)address;
    if (error) *error = nullptr;
}

void GoWSK_accounts_keystore_TimedUnlock(
    GoWSKHandle handle, const char* address, const char* passphrase,
    unsigned long timeout, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_TimedUnlock");
    (void)handle; (void)address; (void)passphrase; (void)timeout;
    if (error) *error = nullptr;
}

void GoWSK_accounts_keystore_Update(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Update");
    (void)handle; (void)address; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
}

char* GoWSK_accounts_keystore_SignHash(
    GoWSKHandle handle, const char* address, const char* hashHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_SignHash");
    (void)handle; (void)address; (void)hashHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_SignHash");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_SignHashWithPassphrase(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* hashHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_SignHashWithPassphrase");
    (void)handle; (void)address; (void)passphrase; (void)hashHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_SignHashWithPassphrase");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_ImportECDSA(
    GoWSKHandle handle, const char* privateKeyHex, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_ImportECDSA");
    (void)handle; (void)privateKeyHex; (void)passphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_ImportECDSA");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_SignTx(
    GoWSKHandle handle, const char* address, const char* txJSON,
    const char* chainIDHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_SignTx");
    (void)handle; (void)address; (void)txJSON; (void)chainIDHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_SignTx");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_SignTxWithPassphrase(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* txJSON, const char* chainIDHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_SignTxWithPassphrase");
    (void)handle; (void)address; (void)passphrase; (void)txJSON; (void)chainIDHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_SignTxWithPassphrase");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keystore_Find(
    GoWSKHandle handle, const char* address, const char* url, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keystore_Find");
    (void)handle; (void)address; (void)url;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keystore_Find");
    return strdup(ret ? ret : "");
}

// ── Extended Keystore ───────────────────────────────────────────────────────

GoWSKHandle GoWSK_accounts_extkeystore_NewKeyStore(
    const char* dir, int scryptN, int scryptP, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_NewKeyStore");
    (void)dir; (void)scryptN; (void)scryptP;
    if (error) *error = nullptr;
    return static_cast<GoWSKHandle>(
        LogosCMockStore::instance().getReturn<int>("GoWSK_accounts_extkeystore_NewKeyStore"));
}

void GoWSK_accounts_extkeystore_CloseKeyStore(GoWSKHandle handle) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_CloseKeyStore");
    (void)handle;
}

char* GoWSK_accounts_extkeystore_Accounts(GoWSKHandle handle, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Accounts");
    (void)handle;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_Accounts");
    return strdup(ret ? ret : "[]");
}

char* GoWSK_accounts_extkeystore_NewAccount(GoWSKHandle handle, const char* passphrase, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_NewAccount");
    (void)handle; (void)passphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_NewAccount");
    return strdup(ret ? ret : "0x0000");
}

char* GoWSK_accounts_extkeystore_Import(
    GoWSKHandle handle, const char* keyJSON, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Import");
    (void)handle; (void)keyJSON; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_Import");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_ImportExtendedKey(
    GoWSKHandle handle, const char* extKeyStr, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_ImportExtendedKey");
    (void)handle; (void)extKeyStr; (void)passphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_ImportExtendedKey");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_ExportExt(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_ExportExt");
    (void)handle; (void)address; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_ExportExt");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_ExportPriv(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_ExportPriv");
    (void)handle; (void)address; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_ExportPriv");
    return strdup(ret ? ret : "");
}

void GoWSK_accounts_extkeystore_Delete(
    GoWSKHandle handle, const char* address, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Delete");
    (void)handle; (void)address; (void)passphrase;
    if (error) *error = nullptr;
}

int GoWSK_accounts_extkeystore_HasAddress(GoWSKHandle handle, const char* address, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_HasAddress");
    (void)handle; (void)address;
    if (error) *error = nullptr;
    return LOGOS_CMOCK_RETURN(int, "GoWSK_accounts_extkeystore_HasAddress");
}

void GoWSK_accounts_extkeystore_Unlock(
    GoWSKHandle handle, const char* address, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Unlock");
    (void)handle; (void)address; (void)passphrase;
    if (error) *error = nullptr;
}

void GoWSK_accounts_extkeystore_Lock(GoWSKHandle handle, const char* address, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Lock");
    (void)handle; (void)address;
    if (error) *error = nullptr;
}

void GoWSK_accounts_extkeystore_TimedUnlock(
    GoWSKHandle handle, const char* address, const char* passphrase,
    unsigned long timeout, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_TimedUnlock");
    (void)handle; (void)address; (void)passphrase; (void)timeout;
    if (error) *error = nullptr;
}

void GoWSK_accounts_extkeystore_Update(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Update");
    (void)handle; (void)address; (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
}

char* GoWSK_accounts_extkeystore_SignHash(
    GoWSKHandle handle, const char* address, const char* hashHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_SignHash");
    (void)handle; (void)address; (void)hashHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_SignHash");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_SignHashWithPassphrase(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* hashHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_SignHashWithPassphrase");
    (void)handle; (void)address; (void)passphrase; (void)hashHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_SignHashWithPassphrase");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_SignTx(
    GoWSKHandle handle, const char* address, const char* txJSON,
    const char* chainIDHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_SignTx");
    (void)handle; (void)address; (void)txJSON; (void)chainIDHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_SignTx");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_SignTxWithPassphrase(
    GoWSKHandle handle, const char* address, const char* passphrase,
    const char* txJSON, const char* chainIDHex, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_SignTxWithPassphrase");
    (void)handle; (void)address; (void)passphrase; (void)txJSON; (void)chainIDHex;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_SignTxWithPassphrase");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_Derive(
    GoWSKHandle handle, const char* address, const char* derivationPath,
    int pin, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Derive");
    (void)handle; (void)address; (void)derivationPath; (void)pin;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_Derive");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_DeriveWithPassphrase(
    GoWSKHandle handle, const char* address, const char* derivationPath,
    int pin, const char* passphrase, const char* newPassphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_DeriveWithPassphrase");
    (void)handle; (void)address; (void)derivationPath; (void)pin;
    (void)passphrase; (void)newPassphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_DeriveWithPassphrase");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_extkeystore_Find(
    GoWSKHandle handle, const char* address, const char* url, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_extkeystore_Find");
    (void)handle; (void)address; (void)url;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_extkeystore_Find");
    return strdup(ret ? ret : "");
}

// ── Key Operations ──────────────────────────────────────────────────────────

char* GoWSK_accounts_keys_CreateExtKeyFromMnemonic(
    const char* phrase, const char* passphrase, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keys_CreateExtKeyFromMnemonic");
    (void)phrase; (void)passphrase;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keys_CreateExtKeyFromMnemonic");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keys_DeriveExtKey(
    const char* extKeyStr, const char* pathStr, char** error)
{
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keys_DeriveExtKey");
    (void)extKeyStr; (void)pathStr;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keys_DeriveExtKey");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keys_ExtKeyToECDSA(const char* extKeyStr, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keys_ExtKeyToECDSA");
    (void)extKeyStr;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keys_ExtKeyToECDSA");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keys_ECDSAToPublicKey(const char* privateKeyStr, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keys_ECDSAToPublicKey");
    (void)privateKeyStr;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keys_ECDSAToPublicKey");
    return strdup(ret ? ret : "");
}

char* GoWSK_accounts_keys_PublicKeyToAddress(const char* publicKeyStr, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_keys_PublicKeyToAddress");
    (void)publicKeyStr;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_keys_PublicKeyToAddress");
    return strdup(ret ? ret : "");
}

// ── Mnemonic Operations ─────────────────────────────────────────────────────

char* GoWSK_accounts_mnemonic_CreateRandomMnemonic(int length, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_mnemonic_CreateRandomMnemonic");
    (void)length;
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_mnemonic_CreateRandomMnemonic");
    return strdup(ret ? ret : "abandon abandon abandon");
}

char* GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength(char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength");
    if (error) *error = nullptr;
    const char* ret = LOGOS_CMOCK_RETURN_STRING("GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength");
    return strdup(ret ? ret : "abandon abandon abandon");
}

uint32_t GoWSK_accounts_mnemonic_LengthToEntropyStrength(int length, char** error) {
    LOGOS_CMOCK_RECORD("GoWSK_accounts_mnemonic_LengthToEntropyStrength");
    (void)length;
    if (error) *error = nullptr;
    return LogosCMockStore::instance().getReturn<uint32_t>("GoWSK_accounts_mnemonic_LengthToEntropyStrength");
}

} // extern "C"
