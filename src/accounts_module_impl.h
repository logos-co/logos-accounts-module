#pragma once

#include <string>
#include <vector>
#include <cstdint>

extern "C" {
    #include "lib/libgowalletsdk.h"
}

class AccountsModuleImpl {
public:
    AccountsModuleImpl();
    ~AccountsModuleImpl();

    // Keystore operations
    bool initKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP);
    bool closeKeystore(const std::string& privateKey);
    std::vector<std::string> keystoreAccounts();
    std::string keystoreNewAccount(const std::string& passphrase);
    std::string keystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase);
    std::string keystoreExport(const std::string& address, const std::string& passphrase, const std::string& newPassphrase);
    bool keystoreDelete(const std::string& address, const std::string& passphrase);
    bool keystoreHasAddress(const std::string& address);
    bool keystoreUnlock(const std::string& address, const std::string& passphrase);
    bool keystoreLock(const std::string& address);
    bool keystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds);
    bool keystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase);
    std::string keystoreSignHash(const std::string& address, const std::string& hashHex);
    std::string keystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex);
    std::string keystoreImportECDSA(const std::string& privateKeyHex, const std::string& passphrase);
    std::string keystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex);
    std::string keystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex);
    std::string keystoreFind(const std::string& address, const std::string& url);

    // Extended keystore operations
    bool initExtKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP);
    bool closeExtKeystore();
    std::vector<std::string> extKeystoreAccounts();
    std::string extKeystoreNewAccount(const std::string& passphrase);
    std::string extKeystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase);
    std::string extKeystoreImportExtendedKey(const std::string& extKeyStr, const std::string& passphrase);
    std::string extKeystoreExportExt(const std::string& address, const std::string& passphrase, const std::string& newPassphrase);
    std::string extKeystoreExportPriv(const std::string& address, const std::string& passphrase, const std::string& newPassphrase);
    bool extKeystoreDelete(const std::string& address, const std::string& passphrase);
    bool extKeystoreHasAddress(const std::string& address);
    bool extKeystoreUnlock(const std::string& address, const std::string& passphrase);
    bool extKeystoreLock(const std::string& address);
    bool extKeystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds);
    bool extKeystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase);
    std::string extKeystoreSignHash(const std::string& address, const std::string& hashHex);
    std::string extKeystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex);
    std::string extKeystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex);
    std::string extKeystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex);
    std::string extKeystoreDerive(const std::string& address, const std::string& derivationPath, int64_t pin);
    std::string extKeystoreDeriveWithPassphrase(const std::string& address, const std::string& derivationPath, int64_t pin, const std::string& passphrase, const std::string& newPassphrase);
    std::string extKeystoreFind(const std::string& address, const std::string& url);

    // Key operations
    std::string createExtKeyFromMnemonic(const std::string& phrase, const std::string& passphrase);
    std::string deriveExtKey(const std::string& extKeyStr, const std::string& pathStr);
    std::string extKeyToECDSA(const std::string& extKeyStr);
    std::string ecdsaToPublicKey(const std::string& privateKeyECDSAStr);
    std::string publicKeyToAddress(const std::string& publicKeyStr);

    // Mnemonic operations
    std::string createRandomMnemonic(int64_t length);
    std::string createRandomMnemonicWithDefaultLength();
    int64_t lengthToEntropyStrength(int64_t length);

private:
    // Helper to parse JSON array of account objects into vector of compact JSON strings
    std::vector<std::string> parseAccountsJson(const char* jsonStr);

    unsigned long long keystoreHandle;
    unsigned long long extkeystoreHandle;
};
