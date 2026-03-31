#include "accounts_module_impl.h"
#include <cstdio>
#include <nlohmann/json.hpp>

AccountsModuleImpl::AccountsModuleImpl() : keystoreHandle(0), extkeystoreHandle(0)
{
    fprintf(stderr, "AccountsModuleImpl: Initializing...\n");
}

AccountsModuleImpl::~AccountsModuleImpl()
{
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
        keystoreHandle = 0;
    }
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
        extkeystoreHandle = 0;
    }
}

std::vector<std::string> AccountsModuleImpl::parseAccountsJson(const char* jsonStr)
{
    std::vector<std::string> addresses;
    try {
        auto doc = nlohmann::json::parse(jsonStr);
        if (!doc.is_array()) {
            fprintf(stderr, "AccountsModuleImpl: Failed to parse accounts JSON: not an array\n");
            return addresses;
        }
        for (const auto& value : doc) {
            if (value.is_object()) {
                addresses.push_back(value.dump());
            }
        }
    } catch (const nlohmann::json::parse_error& e) {
        fprintf(stderr, "AccountsModuleImpl: Failed to parse accounts JSON: %s\n", e.what());
    }
    return addresses;
}

// Keystore operations

bool AccountsModuleImpl::initKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP)
{
    fprintf(stderr, "AccountsModuleImpl::initKeystore %s %lld %lld\n", dir.c_str(), (long long)scryptN, (long long)scryptP);
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
    }
    char* err = nullptr;
    keystoreHandle = GoWSK_accounts_keystore_NewKeyStore(
        const_cast<char*>(dir.c_str()), static_cast<int>(scryptN), static_cast<int>(scryptP), &err);
    if (keystoreHandle == 0) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Failed to create keystore: %s\n", emsg.c_str());
        return false;
    }
    fprintf(stderr, "AccountsModuleImpl: Keystore created: handle=%llu\n", (unsigned long long)keystoreHandle);
    return true;
}

bool AccountsModuleImpl::closeKeystore(const std::string& privateKey)
{
    (void)privateKey;
    fprintf(stderr, "AccountsModuleImpl::closeKeystore\n");
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
        keystoreHandle = 0;
        return true;
    }
    return false;
}

std::vector<std::string> AccountsModuleImpl::keystoreAccounts()
{
    fprintf(stderr, "AccountsModuleImpl::keystoreAccounts\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_keystore_Accounts(keystoreHandle, &err);
    if (accountsJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Accounts error: %s\n", emsg.c_str());
        return {};
    }
    auto result = parseAccountsJson(accountsJson);
    GoWSK_FreeCString(accountsJson);
    return result;
}

std::string AccountsModuleImpl::keystoreNewAccount(const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreNewAccount\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_NewAccount(
        keystoreHandle, const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: NewAccount error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreImport\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_Import(
        keystoreHandle, const_cast<char*>(keyJSON.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Import error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreExport(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreExport\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* keyJson = GoWSK_accounts_keystore_Export(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (keyJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Export error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(keyJson);
    GoWSK_FreeCString(keyJson);
    return result;
}

bool AccountsModuleImpl::keystoreDelete(const std::string& address, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreDelete\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Delete(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Delete error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreHasAddress(const std::string& address)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreHasAddress\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    int result = GoWSK_accounts_keystore_HasAddress(
        keystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: HasAddress error: %s\n", emsg.c_str());
        return false;
    }
    return result != 0;
}

bool AccountsModuleImpl::keystoreUnlock(const std::string& address, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreUnlock\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Unlock(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Unlock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreLock(const std::string& address)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreLock\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Lock(
        keystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Lock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreTimedUnlock\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_TimedUnlock(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()),
        static_cast<unsigned long>(timeoutSeconds), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: TimedUnlock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreUpdate\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Update(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Update error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

std::string AccountsModuleImpl::keystoreSignHash(const std::string& address, const std::string& hashHex)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreSignHash\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHash(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: SignHash error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::keystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreSignHashWithPassphrase\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHashWithPassphrase(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: SignHashWithPassphrase error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::keystoreImportECDSA(const std::string& privateKeyHex, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreImportECDSA\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_ImportECDSA(
        keystoreHandle, const_cast<char*>(privateKeyHex.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ImportECDSA error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreSignTx\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_keystore_SignTx(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(txJSON.c_str()), const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: SignTx error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::keystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreSignTxWithPassphrase\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_keystore_SignTxWithPassphrase(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(txJSON.c_str()),
        const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: SignTxWithPassphrase error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::keystoreFind(const std::string& address, const std::string& url)
{
    fprintf(stderr, "AccountsModuleImpl::keystoreFind\n");
    if (keystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_keystore_Find(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(url.c_str()), &err);
    if (resultStr == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Find error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Extended keystore operations

bool AccountsModuleImpl::initExtKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP)
{
    fprintf(stderr, "AccountsModuleImpl::initExtKeystore %s %lld %lld\n", dir.c_str(), (long long)scryptN, (long long)scryptP);
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
    }
    char* err = nullptr;
    extkeystoreHandle = GoWSK_accounts_extkeystore_NewKeyStore(
        const_cast<char*>(dir.c_str()), static_cast<int>(scryptN), static_cast<int>(scryptP), &err);
    if (extkeystoreHandle == 0) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: Failed to create ext keystore: %s\n", emsg.c_str());
        return false;
    }
    fprintf(stderr, "AccountsModuleImpl: Ext keystore created: handle=%llu\n", (unsigned long long)extkeystoreHandle);
    return true;
}

bool AccountsModuleImpl::closeExtKeystore()
{
    fprintf(stderr, "AccountsModuleImpl::closeExtKeystore\n");
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
        extkeystoreHandle = 0;
        return true;
    }
    return false;
}

std::vector<std::string> AccountsModuleImpl::extKeystoreAccounts()
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreAccounts\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_extkeystore_Accounts(extkeystoreHandle, &err);
    if (accountsJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtAccounts error: %s\n", emsg.c_str());
        return {};
    }
    auto result = parseAccountsJson(accountsJson);
    GoWSK_FreeCString(accountsJson);
    return result;
}

std::string AccountsModuleImpl::extKeystoreNewAccount(const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreNewAccount\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_NewAccount(
        extkeystoreHandle, const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtNewAccount error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreImport\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_Import(
        extkeystoreHandle, const_cast<char*>(keyJSON.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtImport error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreImportExtendedKey(const std::string& extKeyStr, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreImportExtendedKey\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_ImportExtendedKey(
        extkeystoreHandle, const_cast<char*>(extKeyStr.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtImportExtendedKey error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreExportExt(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreExportExt\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* extKey = GoWSK_accounts_extkeystore_ExportExt(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (extKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtExportExt error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

std::string AccountsModuleImpl::extKeystoreExportPriv(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreExportPriv\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* privKey = GoWSK_accounts_extkeystore_ExportPriv(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (privKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtExportPriv error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(privKey);
    GoWSK_FreeCString(privKey);
    return result;
}

bool AccountsModuleImpl::extKeystoreDelete(const std::string& address, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreDelete\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Delete(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtDelete error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreHasAddress(const std::string& address)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreHasAddress\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    int result = GoWSK_accounts_extkeystore_HasAddress(
        extkeystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtHasAddress error: %s\n", emsg.c_str());
        return false;
    }
    return result != 0;
}

bool AccountsModuleImpl::extKeystoreUnlock(const std::string& address, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreUnlock\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Unlock(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtUnlock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreLock(const std::string& address)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreLock\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Lock(
        extkeystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtLock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreTimedUnlock\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_TimedUnlock(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()),
        static_cast<unsigned long>(timeoutSeconds), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtTimedUnlock error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreUpdate\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Update(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtUpdate error: %s\n", emsg.c_str());
        return false;
    }
    return true;
}

std::string AccountsModuleImpl::extKeystoreSignHash(const std::string& address, const std::string& hashHex)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreSignHash\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHash(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtSignHash error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreSignHashWithPassphrase\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHashWithPassphrase(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtSignHashWithPassphrase error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreSignTx\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_extkeystore_SignTx(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(txJSON.c_str()), const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtSignTx error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreSignTxWithPassphrase\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_extkeystore_SignTxWithPassphrase(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(txJSON.c_str()),
        const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtSignTxWithPassphrase error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::extKeystoreDerive(const std::string& address, const std::string& derivationPath, int64_t pin)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreDerive\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* derivedAddress = GoWSK_accounts_extkeystore_Derive(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(derivationPath.c_str()), static_cast<int>(pin), &err);
    if (derivedAddress == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtDerive error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

std::string AccountsModuleImpl::extKeystoreDeriveWithPassphrase(const std::string& address, const std::string& derivationPath, int64_t pin, const std::string& passphrase, const std::string& newPassphrase)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreDeriveWithPassphrase\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* derivedAddress = GoWSK_accounts_extkeystore_DeriveWithPassphrase(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(derivationPath.c_str()), static_cast<int>(pin),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (derivedAddress == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtDeriveWithPassphrase error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

std::string AccountsModuleImpl::extKeystoreFind(const std::string& address, const std::string& url)
{
    fprintf(stderr, "AccountsModuleImpl::extKeystoreFind\n");
    if (extkeystoreHandle == 0) {
        fprintf(stderr, "AccountsModuleImpl: Ext keystore not initialized\n");
        return {};
    }
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_extkeystore_Find(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(url.c_str()), &err);
    if (resultStr == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtFind error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Key operations

std::string AccountsModuleImpl::createExtKeyFromMnemonic(const std::string& phrase, const std::string& passphrase)
{
    fprintf(stderr, "AccountsModuleImpl::createExtKeyFromMnemonic\n");
    char* err = nullptr;
    char* extKey = GoWSK_accounts_keys_CreateExtKeyFromMnemonic(
        const_cast<char*>(phrase.c_str()), const_cast<char*>(passphrase.c_str()), &err);
    if (extKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: CreateExtKeyFromMnemonic error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

std::string AccountsModuleImpl::deriveExtKey(const std::string& extKeyStr, const std::string& pathStr)
{
    fprintf(stderr, "AccountsModuleImpl::deriveExtKey\n");
    char* err = nullptr;
    char* derivedKey = GoWSK_accounts_keys_DeriveExtKey(
        const_cast<char*>(extKeyStr.c_str()), const_cast<char*>(pathStr.c_str()), &err);
    if (derivedKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: DeriveExtKey error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(derivedKey);
    GoWSK_FreeCString(derivedKey);
    return result;
}

std::string AccountsModuleImpl::extKeyToECDSA(const std::string& extKeyStr)
{
    fprintf(stderr, "AccountsModuleImpl::extKeyToECDSA\n");
    char* err = nullptr;
    char* ecdsaKey = GoWSK_accounts_keys_ExtKeyToECDSA(
        const_cast<char*>(extKeyStr.c_str()), &err);
    if (ecdsaKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ExtKeyToECDSA error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(ecdsaKey);
    GoWSK_FreeCString(ecdsaKey);
    return result;
}

std::string AccountsModuleImpl::ecdsaToPublicKey(const std::string& privateKeyECDSAStr)
{
    fprintf(stderr, "AccountsModuleImpl::ecdsaToPublicKey\n");
    char* err = nullptr;
    char* publicKey = GoWSK_accounts_keys_ECDSAToPublicKey(
        const_cast<char*>(privateKeyECDSAStr.c_str()), &err);
    if (publicKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: ECDSAToPublicKey error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(publicKey);
    GoWSK_FreeCString(publicKey);
    return result;
}

std::string AccountsModuleImpl::publicKeyToAddress(const std::string& publicKeyStr)
{
    fprintf(stderr, "AccountsModuleImpl::publicKeyToAddress\n");
    char* err = nullptr;
    char* address = GoWSK_accounts_keys_PublicKeyToAddress(
        const_cast<char*>(publicKeyStr.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: PublicKeyToAddress error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

// Mnemonic operations

std::string AccountsModuleImpl::createRandomMnemonic(int64_t length)
{
    fprintf(stderr, "AccountsModuleImpl::createRandomMnemonic %lld\n", (long long)length);
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonic(static_cast<int>(length), &err);
    if (mnemonic == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: CreateRandomMnemonic error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

std::string AccountsModuleImpl::createRandomMnemonicWithDefaultLength()
{
    fprintf(stderr, "AccountsModuleImpl::createRandomMnemonicWithDefaultLength\n");
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength(&err);
    if (mnemonic == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: CreateRandomMnemonicWithDefaultLength error: %s\n", emsg.c_str());
        return {};
    }
    std::string result(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

int64_t AccountsModuleImpl::lengthToEntropyStrength(int64_t length)
{
    fprintf(stderr, "AccountsModuleImpl::lengthToEntropyStrength %lld\n", (long long)length);
    char* err = nullptr;
    uint32_t result = GoWSK_accounts_mnemonic_LengthToEntropyStrength(static_cast<int>(length), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        fprintf(stderr, "AccountsModuleImpl: LengthToEntropyStrength error: %s\n", emsg.c_str());
        return 0;
    }
    return static_cast<int64_t>(result);
}
