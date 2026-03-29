#include "accounts_module_impl.h"
#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonParseError>

AccountsModuleImpl::AccountsModuleImpl() : keystoreHandle(0), extkeystoreHandle(0)
{
    qDebug() << "AccountsModuleImpl: Initializing...";
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
    QString result = QString::fromUtf8(jsonStr);

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "AccountsModuleImpl: Failed to parse accounts JSON:" << parseError.errorString();
        return addresses;
    }
    if (doc.isNull() || !doc.isArray()) {
        qWarning() << "AccountsModuleImpl: Failed to parse accounts JSON: not an array";
        return addresses;
    }

    for (const QJsonValue &value : doc.array()) {
        if (value.isObject()) {
            QJsonObject obj = value.toObject();
            QJsonDocument objDoc(obj);
            addresses.push_back(objDoc.toJson(QJsonDocument::Compact).toStdString());
        }
    }
    return addresses;
}

// Keystore operations

bool AccountsModuleImpl::initKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP)
{
    qDebug() << "AccountsModuleImpl::initKeystore" << dir.c_str() << scryptN << scryptP;
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
    }
    char* err = nullptr;
    keystoreHandle = GoWSK_accounts_keystore_NewKeyStore(
        const_cast<char*>(dir.c_str()), static_cast<int>(scryptN), static_cast<int>(scryptP), &err);
    if (keystoreHandle == 0) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Failed to create keystore:" << emsg.c_str();
        return false;
    }
    qDebug() << "AccountsModuleImpl: Keystore created: handle=" << (qulonglong)keystoreHandle;
    return true;
}

bool AccountsModuleImpl::closeKeystore(const std::string& privateKey)
{
    Q_UNUSED(privateKey);
    qDebug() << "AccountsModuleImpl::closeKeystore";
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
        keystoreHandle = 0;
        return true;
    }
    return false;
}

std::vector<std::string> AccountsModuleImpl::keystoreAccounts()
{
    qDebug() << "AccountsModuleImpl::keystoreAccounts";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_keystore_Accounts(keystoreHandle, &err);
    if (accountsJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Accounts error:" << emsg.c_str();
        return {};
    }
    auto result = parseAccountsJson(accountsJson);
    GoWSK_FreeCString(accountsJson);
    return result;
}

std::string AccountsModuleImpl::keystoreNewAccount(const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreNewAccount";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_NewAccount(
        keystoreHandle, const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: NewAccount error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreImport";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_Import(
        keystoreHandle, const_cast<char*>(keyJSON.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Import error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreExport(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreExport";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* keyJson = GoWSK_accounts_keystore_Export(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (keyJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Export error:" << emsg.c_str();
        return {};
    }
    std::string result(keyJson);
    GoWSK_FreeCString(keyJson);
    return result;
}

bool AccountsModuleImpl::keystoreDelete(const std::string& address, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreDelete";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Delete(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Delete error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreHasAddress(const std::string& address)
{
    qDebug() << "AccountsModuleImpl::keystoreHasAddress";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return false;
    }
    char* err = nullptr;
    int result = GoWSK_accounts_keystore_HasAddress(
        keystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: HasAddress error:" << emsg.c_str();
        return false;
    }
    return result != 0;
}

bool AccountsModuleImpl::keystoreUnlock(const std::string& address, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreUnlock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Unlock(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Unlock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreLock(const std::string& address)
{
    qDebug() << "AccountsModuleImpl::keystoreLock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Lock(
        keystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Lock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds)
{
    qDebug() << "AccountsModuleImpl::keystoreTimedUnlock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
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
        qWarning() << "AccountsModuleImpl: TimedUnlock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::keystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreUpdate";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_keystore_Update(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Update error:" << emsg.c_str();
        return false;
    }
    return true;
}

std::string AccountsModuleImpl::keystoreSignHash(const std::string& address, const std::string& hashHex)
{
    qDebug() << "AccountsModuleImpl::keystoreSignHash";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHash(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: SignHash error:" << emsg.c_str();
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::keystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex)
{
    qDebug() << "AccountsModuleImpl::keystoreSignHashWithPassphrase";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHashWithPassphrase(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: SignHashWithPassphrase error:" << emsg.c_str();
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::keystoreImportECDSA(const std::string& privateKeyHex, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::keystoreImportECDSA";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_ImportECDSA(
        keystoreHandle, const_cast<char*>(privateKeyHex.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ImportECDSA error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::keystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex)
{
    qDebug() << "AccountsModuleImpl::keystoreSignTx";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_keystore_SignTx(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(txJSON.c_str()), const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: SignTx error:" << emsg.c_str();
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::keystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex)
{
    qDebug() << "AccountsModuleImpl::keystoreSignTxWithPassphrase";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
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
        qWarning() << "AccountsModuleImpl: SignTxWithPassphrase error:" << emsg.c_str();
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::keystoreFind(const std::string& address, const std::string& url)
{
    qDebug() << "AccountsModuleImpl::keystoreFind";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_keystore_Find(
        keystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(url.c_str()), &err);
    if (resultStr == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Find error:" << emsg.c_str();
        return {};
    }
    std::string result(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Extended keystore operations

bool AccountsModuleImpl::initExtKeystore(const std::string& dir, int64_t scryptN, int64_t scryptP)
{
    qDebug() << "AccountsModuleImpl::initExtKeystore" << dir.c_str() << scryptN << scryptP;
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
    }
    char* err = nullptr;
    extkeystoreHandle = GoWSK_accounts_extkeystore_NewKeyStore(
        const_cast<char*>(dir.c_str()), static_cast<int>(scryptN), static_cast<int>(scryptP), &err);
    if (extkeystoreHandle == 0) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: Failed to create ext keystore:" << emsg.c_str();
        return false;
    }
    qDebug() << "AccountsModuleImpl: Ext keystore created: handle=" << (qulonglong)extkeystoreHandle;
    return true;
}

bool AccountsModuleImpl::closeExtKeystore()
{
    qDebug() << "AccountsModuleImpl::closeExtKeystore";
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
        extkeystoreHandle = 0;
        return true;
    }
    return false;
}

std::vector<std::string> AccountsModuleImpl::extKeystoreAccounts()
{
    qDebug() << "AccountsModuleImpl::extKeystoreAccounts";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_extkeystore_Accounts(extkeystoreHandle, &err);
    if (accountsJson == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtAccounts error:" << emsg.c_str();
        return {};
    }
    auto result = parseAccountsJson(accountsJson);
    GoWSK_FreeCString(accountsJson);
    return result;
}

std::string AccountsModuleImpl::extKeystoreNewAccount(const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreNewAccount";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_NewAccount(
        extkeystoreHandle, const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtNewAccount error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreImport(const std::string& keyJSON, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreImport";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_Import(
        extkeystoreHandle, const_cast<char*>(keyJSON.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtImport error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreImportExtendedKey(const std::string& extKeyStr, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreImportExtendedKey";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_ImportExtendedKey(
        extkeystoreHandle, const_cast<char*>(extKeyStr.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtImportExtendedKey error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

std::string AccountsModuleImpl::extKeystoreExportExt(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreExportExt";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* extKey = GoWSK_accounts_extkeystore_ExportExt(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (extKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtExportExt error:" << emsg.c_str();
        return {};
    }
    std::string result(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

std::string AccountsModuleImpl::extKeystoreExportPriv(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreExportPriv";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* privKey = GoWSK_accounts_extkeystore_ExportPriv(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (privKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtExportPriv error:" << emsg.c_str();
        return {};
    }
    std::string result(privKey);
    GoWSK_FreeCString(privKey);
    return result;
}

bool AccountsModuleImpl::extKeystoreDelete(const std::string& address, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreDelete";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Delete(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtDelete error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreHasAddress(const std::string& address)
{
    qDebug() << "AccountsModuleImpl::extKeystoreHasAddress";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return false;
    }
    char* err = nullptr;
    int result = GoWSK_accounts_extkeystore_HasAddress(
        extkeystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtHasAddress error:" << emsg.c_str();
        return false;
    }
    return result != 0;
}

bool AccountsModuleImpl::extKeystoreUnlock(const std::string& address, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreUnlock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Unlock(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtUnlock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreLock(const std::string& address)
{
    qDebug() << "AccountsModuleImpl::extKeystoreLock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Lock(
        extkeystoreHandle, const_cast<char*>(address.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtLock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreTimedUnlock(const std::string& address, const std::string& passphrase, uint64_t timeoutSeconds)
{
    qDebug() << "AccountsModuleImpl::extKeystoreTimedUnlock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
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
        qWarning() << "AccountsModuleImpl: ExtTimedUnlock error:" << emsg.c_str();
        return false;
    }
    return true;
}

bool AccountsModuleImpl::extKeystoreUpdate(const std::string& address, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreUpdate";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return false;
    }
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Update(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(newPassphrase.c_str()), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtUpdate error:" << emsg.c_str();
        return false;
    }
    return true;
}

std::string AccountsModuleImpl::extKeystoreSignHash(const std::string& address, const std::string& hashHex)
{
    qDebug() << "AccountsModuleImpl::extKeystoreSignHash";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHash(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtSignHash error:" << emsg.c_str();
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignHashWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& hashHex)
{
    qDebug() << "AccountsModuleImpl::extKeystoreSignHashWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHashWithPassphrase(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(passphrase.c_str()), const_cast<char*>(hashHex.c_str()), &err);
    if (signature == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtSignHashWithPassphrase error:" << emsg.c_str();
        return {};
    }
    std::string result(signature);
    GoWSK_FreeCString(signature);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignTx(const std::string& address, const std::string& txJSON, const std::string& chainIDHex)
{
    qDebug() << "AccountsModuleImpl::extKeystoreSignTx";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_extkeystore_SignTx(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(txJSON.c_str()), const_cast<char*>(chainIDHex.c_str()), &err);
    if (signedTx == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtSignTx error:" << emsg.c_str();
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::extKeystoreSignTxWithPassphrase(const std::string& address, const std::string& passphrase, const std::string& txJSON, const std::string& chainIDHex)
{
    qDebug() << "AccountsModuleImpl::extKeystoreSignTxWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
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
        qWarning() << "AccountsModuleImpl: ExtSignTxWithPassphrase error:" << emsg.c_str();
        return {};
    }
    std::string result(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

std::string AccountsModuleImpl::extKeystoreDerive(const std::string& address, const std::string& derivationPath, int64_t pin)
{
    qDebug() << "AccountsModuleImpl::extKeystoreDerive";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* derivedAddress = GoWSK_accounts_extkeystore_Derive(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(derivationPath.c_str()), static_cast<int>(pin), &err);
    if (derivedAddress == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtDerive error:" << emsg.c_str();
        return {};
    }
    std::string result(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

std::string AccountsModuleImpl::extKeystoreDeriveWithPassphrase(const std::string& address, const std::string& derivationPath, int64_t pin, const std::string& passphrase, const std::string& newPassphrase)
{
    qDebug() << "AccountsModuleImpl::extKeystoreDeriveWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
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
        qWarning() << "AccountsModuleImpl: ExtDeriveWithPassphrase error:" << emsg.c_str();
        return {};
    }
    std::string result(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

std::string AccountsModuleImpl::extKeystoreFind(const std::string& address, const std::string& url)
{
    qDebug() << "AccountsModuleImpl::extKeystoreFind";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModuleImpl: Ext keystore not initialized";
        return {};
    }
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_extkeystore_Find(
        extkeystoreHandle, const_cast<char*>(address.c_str()),
        const_cast<char*>(url.c_str()), &err);
    if (resultStr == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtFind error:" << emsg.c_str();
        return {};
    }
    std::string result(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Key operations

std::string AccountsModuleImpl::createExtKeyFromMnemonic(const std::string& phrase, const std::string& passphrase)
{
    qDebug() << "AccountsModuleImpl::createExtKeyFromMnemonic";
    char* err = nullptr;
    char* extKey = GoWSK_accounts_keys_CreateExtKeyFromMnemonic(
        const_cast<char*>(phrase.c_str()), const_cast<char*>(passphrase.c_str()), &err);
    if (extKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: CreateExtKeyFromMnemonic error:" << emsg.c_str();
        return {};
    }
    std::string result(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

std::string AccountsModuleImpl::deriveExtKey(const std::string& extKeyStr, const std::string& pathStr)
{
    qDebug() << "AccountsModuleImpl::deriveExtKey";
    char* err = nullptr;
    char* derivedKey = GoWSK_accounts_keys_DeriveExtKey(
        const_cast<char*>(extKeyStr.c_str()), const_cast<char*>(pathStr.c_str()), &err);
    if (derivedKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: DeriveExtKey error:" << emsg.c_str();
        return {};
    }
    std::string result(derivedKey);
    GoWSK_FreeCString(derivedKey);
    return result;
}

std::string AccountsModuleImpl::extKeyToECDSA(const std::string& extKeyStr)
{
    qDebug() << "AccountsModuleImpl::extKeyToECDSA";
    char* err = nullptr;
    char* ecdsaKey = GoWSK_accounts_keys_ExtKeyToECDSA(
        const_cast<char*>(extKeyStr.c_str()), &err);
    if (ecdsaKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ExtKeyToECDSA error:" << emsg.c_str();
        return {};
    }
    std::string result(ecdsaKey);
    GoWSK_FreeCString(ecdsaKey);
    return result;
}

std::string AccountsModuleImpl::ecdsaToPublicKey(const std::string& privateKeyECDSAStr)
{
    qDebug() << "AccountsModuleImpl::ecdsaToPublicKey";
    char* err = nullptr;
    char* publicKey = GoWSK_accounts_keys_ECDSAToPublicKey(
        const_cast<char*>(privateKeyECDSAStr.c_str()), &err);
    if (publicKey == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: ECDSAToPublicKey error:" << emsg.c_str();
        return {};
    }
    std::string result(publicKey);
    GoWSK_FreeCString(publicKey);
    return result;
}

std::string AccountsModuleImpl::publicKeyToAddress(const std::string& publicKeyStr)
{
    qDebug() << "AccountsModuleImpl::publicKeyToAddress";
    char* err = nullptr;
    char* address = GoWSK_accounts_keys_PublicKeyToAddress(
        const_cast<char*>(publicKeyStr.c_str()), &err);
    if (address == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: PublicKeyToAddress error:" << emsg.c_str();
        return {};
    }
    std::string result(address);
    GoWSK_FreeCString(address);
    return result;
}

// Mnemonic operations

std::string AccountsModuleImpl::createRandomMnemonic(int64_t length)
{
    qDebug() << "AccountsModuleImpl::createRandomMnemonic" << length;
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonic(static_cast<int>(length), &err);
    if (mnemonic == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: CreateRandomMnemonic error:" << emsg.c_str();
        return {};
    }
    std::string result(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

std::string AccountsModuleImpl::createRandomMnemonicWithDefaultLength()
{
    qDebug() << "AccountsModuleImpl::createRandomMnemonicWithDefaultLength";
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength(&err);
    if (mnemonic == nullptr) {
        std::string emsg = err ? std::string(err) : "unknown error";
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: CreateRandomMnemonicWithDefaultLength error:" << emsg.c_str();
        return {};
    }
    std::string result(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

int64_t AccountsModuleImpl::lengthToEntropyStrength(int64_t length)
{
    qDebug() << "AccountsModuleImpl::lengthToEntropyStrength" << length;
    char* err = nullptr;
    uint32_t result = GoWSK_accounts_mnemonic_LengthToEntropyStrength(static_cast<int>(length), &err);
    if (err != nullptr) {
        std::string emsg(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModuleImpl: LengthToEntropyStrength error:" << emsg.c_str();
        return 0;
    }
    return static_cast<int64_t>(result);
}
