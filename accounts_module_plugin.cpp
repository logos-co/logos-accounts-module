#include "accounts_module_plugin.h"
#include <QtCore/QDebug>
#include <QtCore/QVariantList>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonValue>
#include <QtCore/QJsonParseError>

AccountsModulePlugin::AccountsModulePlugin() : keystoreHandle(0), extkeystoreHandle(0)
{
    qDebug() << "AccountsModulePlugin: Initializing...";
}

AccountsModulePlugin::~AccountsModulePlugin()
{
    if (logosAPI) {
        delete logosAPI;
        logosAPI = nullptr;
    }
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
        keystoreHandle = 0;
    }
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
        extkeystoreHandle = 0;
    }
}

void AccountsModulePlugin::initLogos(LogosAPI* logosAPIInstance)
{
    if (logosAPI) {
        delete logosAPI;
    }
    logosAPI = logosAPIInstance;
}

void AccountsModulePlugin::simple_callback(int callerRet, const char* msg, size_t len, void* userData)
{
    Q_UNUSED(userData);
    qDebug() << "AccountsModulePlugin::simple_callback ret:" << callerRet;
    if (msg && len > 0) {
        QString message = QString::fromUtf8(msg, static_cast<int>(len));
        qDebug() << "AccountsModulePlugin::simple_callback message:" << message;
    }
}

// Keystore operations
bool AccountsModulePlugin::initKeystore(const QString &dir, uint scryptN, uint scryptP)
{
    qDebug() << "AccountsModulePlugin::initKeystore" << dir << scryptN << scryptP;
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
    }
    QByteArray dirUtf8 = dir.toUtf8();
    char* err = nullptr;
    keystoreHandle = GoWSK_accounts_keystore_NewKeyStore(dirUtf8.data(), scryptN, scryptP, &err);
    if (keystoreHandle == 0) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Failed to create keystore:" << emsg;
        return false;
    }
    qDebug() << "AccountsModulePlugin: Keystore created: handle=" << (qulonglong)keystoreHandle;
    return true;
}

bool AccountsModulePlugin::closeKeystore(const QString &privateKey)
{
    Q_UNUSED(privateKey);
    qDebug() << "AccountsModulePlugin::closeKeystore";
    if (keystoreHandle != 0) {
        GoWSK_accounts_keystore_CloseKeyStore(keystoreHandle);
        keystoreHandle = 0;
        return true;
    }
    return false;
}

QStringList AccountsModulePlugin::keystoreAccounts()
{
    qDebug() << "AccountsModulePlugin::keystoreAccounts";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QStringList();
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_keystore_Accounts(keystoreHandle, &err);
    if (accountsJson == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Accounts error:" << emsg;
        return QStringList();
    }
    QString result = QString::fromUtf8(accountsJson);
    GoWSK_FreeCString(accountsJson);
    
    // Parse JSON array of addresses
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "AccountsModulePlugin: Failed to parse accounts JSON:" << parseError.errorString();
        return QStringList();
    }
    QStringList addresses;
    if (doc.isArray()) {
        for (const QJsonValue &value : doc.array()) {
            if (value.isString()) {
                addresses.append(value.toString());
            }
        }
    }
    return addresses;
}

QString AccountsModulePlugin::keystoreNewAccount(const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreNewAccount";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_NewAccount(keystoreHandle, passphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: NewAccount error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::keystoreImport(const QString &keyJSON, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreImport";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray keyJsonUtf8 = keyJSON.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_Import(keystoreHandle, keyJsonUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Import error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::keystoreExport(const QString &address, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreExport";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* keyJson = GoWSK_accounts_keystore_Export(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (keyJson == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Export error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(keyJson);
    GoWSK_FreeCString(keyJson);
    return result;
}

bool AccountsModulePlugin::keystoreDelete(const QString &address, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreDelete";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_keystore_Delete(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Delete error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::keystoreHasAddress(const QString &address)
{
    qDebug() << "AccountsModulePlugin::keystoreHasAddress";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    char* err = nullptr;
    int result = GoWSK_accounts_keystore_HasAddress(keystoreHandle, addressUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: HasAddress error:" << emsg;
        return false;
    }
    return result != 0;
}

bool AccountsModulePlugin::keystoreUnlock(const QString &address, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreUnlock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_keystore_Unlock(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Unlock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::keystoreLock(const QString &address)
{
    qDebug() << "AccountsModulePlugin::keystoreLock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_keystore_Lock(keystoreHandle, addressUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Lock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::keystoreTimedUnlock(const QString &address, const QString &passphrase, unsigned long timeoutSeconds)
{
    qDebug() << "AccountsModulePlugin::keystoreTimedUnlock";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_keystore_TimedUnlock(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), timeoutSeconds, &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: TimedUnlock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::keystoreUpdate(const QString &address, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreUpdate";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_keystore_Update(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Update error:" << emsg;
        return false;
    }
    return true;
}

QString AccountsModulePlugin::keystoreSignHash(const QString &address, const QString &hashHex)
{
    qDebug() << "AccountsModulePlugin::keystoreSignHash";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray hashHexUtf8 = hashHex.toUtf8();
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHash(keystoreHandle, addressUtf8.data(), hashHexUtf8.data(), &err);
    if (signature == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: SignHash error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signature);
    GoWSK_FreeCString(signature);
    return result;
}

QString AccountsModulePlugin::keystoreSignHashWithPassphrase(const QString &address, const QString &passphrase, const QString &hashHex)
{
    qDebug() << "AccountsModulePlugin::keystoreSignHashWithPassphrase";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray hashHexUtf8 = hashHex.toUtf8();
    char* err = nullptr;
    char* signature = GoWSK_accounts_keystore_SignHashWithPassphrase(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), hashHexUtf8.data(), &err);
    if (signature == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: SignHashWithPassphrase error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signature);
    GoWSK_FreeCString(signature);
    return result;
}

QString AccountsModulePlugin::keystoreImportECDSA(const QString &privateKeyHex, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::keystoreImportECDSA";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray privateKeyHexUtf8 = privateKeyHex.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_keystore_ImportECDSA(keystoreHandle, privateKeyHexUtf8.data(), passphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ImportECDSA error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::keystoreSignTx(const QString &address, const QString &txJSON, const QString &chainIDHex)
{
    qDebug() << "AccountsModulePlugin::keystoreSignTx";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray txJsonUtf8 = txJSON.toUtf8();
    QByteArray chainIdHexUtf8 = chainIDHex.toUtf8();
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_keystore_SignTx(keystoreHandle, addressUtf8.data(), txJsonUtf8.data(), chainIdHexUtf8.data(), &err);
    if (signedTx == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: SignTx error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

QString AccountsModulePlugin::keystoreSignTxWithPassphrase(const QString &address, const QString &passphrase, const QString &txJSON, const QString &chainIDHex)
{
    qDebug() << "AccountsModulePlugin::keystoreSignTxWithPassphrase";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray txJsonUtf8 = txJSON.toUtf8();
    QByteArray chainIdHexUtf8 = chainIDHex.toUtf8();
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_keystore_SignTxWithPassphrase(keystoreHandle, addressUtf8.data(), passphraseUtf8.data(), txJsonUtf8.data(), chainIdHexUtf8.data(), &err);
    if (signedTx == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: SignTxWithPassphrase error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

QString AccountsModulePlugin::keystoreFind(const QString &address, const QString &url)
{
    qDebug() << "AccountsModulePlugin::keystoreFind";
    if (keystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray urlUtf8 = url.toUtf8();
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_keystore_Find(keystoreHandle, addressUtf8.data(), urlUtf8.data(), &err);
    if (resultStr == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Find error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Extended keystore operations
bool AccountsModulePlugin::initExtKeystore(const QString &dir, uint scryptN, uint scryptP)
{
    qDebug() << "AccountsModulePlugin::initExtKeystore" << dir << scryptN << scryptP;
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
    }
    QByteArray dirUtf8 = dir.toUtf8();
    char* err = nullptr;
    extkeystoreHandle = GoWSK_accounts_extkeystore_NewKeyStore(dirUtf8.data(), scryptN, scryptP, &err);
    if (extkeystoreHandle == 0) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: Failed to create ext keystore:" << emsg;
        return false;
    }
    qDebug() << "AccountsModulePlugin: Ext keystore created: handle=" << (qulonglong)extkeystoreHandle;
    return true;
}

bool AccountsModulePlugin::closeExtKeystore()
{
    qDebug() << "AccountsModulePlugin::closeExtKeystore";
    if (extkeystoreHandle != 0) {
        GoWSK_accounts_extkeystore_CloseKeyStore(extkeystoreHandle);
        extkeystoreHandle = 0;
        return true;
    }
    return false;
}

QStringList AccountsModulePlugin::extKeystoreAccounts()
{
    qDebug() << "AccountsModulePlugin::extKeystoreAccounts";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QStringList();
    }
    char* err = nullptr;
    char* accountsJson = GoWSK_accounts_extkeystore_Accounts(extkeystoreHandle, &err);
    if (accountsJson == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtAccounts error:" << emsg;
        return QStringList();
    }
    QString result = QString::fromUtf8(accountsJson);
    GoWSK_FreeCString(accountsJson);
    
    // Parse JSON array of addresses
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "AccountsModulePlugin: Failed to parse ext accounts JSON:" << parseError.errorString();
        return QStringList();
    }
    QStringList addresses;
    if (doc.isArray()) {
        for (const QJsonValue &value : doc.array()) {
            if (value.isString()) {
                addresses.append(value.toString());
            }
        }
    }
    return addresses;
}

QString AccountsModulePlugin::extKeystoreNewAccount(const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreNewAccount";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_NewAccount(extkeystoreHandle, passphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtNewAccount error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::extKeystoreImport(const QString &keyJSON, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreImport";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray keyJsonUtf8 = keyJSON.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_Import(extkeystoreHandle, keyJsonUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtImport error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::extKeystoreImportExtendedKey(const QString &extKeyStr, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreImportExtendedKey";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray extKeyStrUtf8 = extKeyStr.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_extkeystore_ImportExtendedKey(extkeystoreHandle, extKeyStrUtf8.data(), passphraseUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtImportExtendedKey error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

QString AccountsModulePlugin::extKeystoreExportExt(const QString &address, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreExportExt";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* extKey = GoWSK_accounts_extkeystore_ExportExt(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (extKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtExportExt error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

QString AccountsModulePlugin::extKeystoreExportPriv(const QString &address, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreExportPriv";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* privKey = GoWSK_accounts_extkeystore_ExportPriv(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (privKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtExportPriv error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(privKey);
    GoWSK_FreeCString(privKey);
    return result;
}

bool AccountsModulePlugin::extKeystoreDelete(const QString &address, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreDelete";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Delete(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtDelete error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::extKeystoreHasAddress(const QString &address)
{
    qDebug() << "AccountsModulePlugin::extKeystoreHasAddress";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    char* err = nullptr;
    int result = GoWSK_accounts_extkeystore_HasAddress(extkeystoreHandle, addressUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtHasAddress error:" << emsg;
        return false;
    }
    return result != 0;
}

bool AccountsModulePlugin::extKeystoreUnlock(const QString &address, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreUnlock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Unlock(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtUnlock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::extKeystoreLock(const QString &address)
{
    qDebug() << "AccountsModulePlugin::extKeystoreLock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Lock(extkeystoreHandle, addressUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtLock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::extKeystoreTimedUnlock(const QString &address, const QString &passphrase, unsigned long timeoutSeconds)
{
    qDebug() << "AccountsModulePlugin::extKeystoreTimedUnlock";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_extkeystore_TimedUnlock(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), timeoutSeconds, &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtTimedUnlock error:" << emsg;
        return false;
    }
    return true;
}

bool AccountsModulePlugin::extKeystoreUpdate(const QString &address, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreUpdate";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return false;
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    GoWSK_accounts_extkeystore_Update(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtUpdate error:" << emsg;
        return false;
    }
    return true;
}

QString AccountsModulePlugin::extKeystoreSignHash(const QString &address, const QString &hashHex)
{
    qDebug() << "AccountsModulePlugin::extKeystoreSignHash";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray hashHexUtf8 = hashHex.toUtf8();
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHash(extkeystoreHandle, addressUtf8.data(), hashHexUtf8.data(), &err);
    if (signature == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtSignHash error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signature);
    GoWSK_FreeCString(signature);
    return result;
}

QString AccountsModulePlugin::extKeystoreSignHashWithPassphrase(const QString &address, const QString &passphrase, const QString &hashHex)
{
    qDebug() << "AccountsModulePlugin::extKeystoreSignHashWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray hashHexUtf8 = hashHex.toUtf8();
    char* err = nullptr;
    char* signature = GoWSK_accounts_extkeystore_SignHashWithPassphrase(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), hashHexUtf8.data(), &err);
    if (signature == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtSignHashWithPassphrase error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signature);
    GoWSK_FreeCString(signature);
    return result;
}

QString AccountsModulePlugin::extKeystoreSignTx(const QString &address, const QString &txJSON, const QString &chainIDHex)
{
    qDebug() << "AccountsModulePlugin::extKeystoreSignTx";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray txJsonUtf8 = txJSON.toUtf8();
    QByteArray chainIdHexUtf8 = chainIDHex.toUtf8();
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_extkeystore_SignTx(extkeystoreHandle, addressUtf8.data(), txJsonUtf8.data(), chainIdHexUtf8.data(), &err);
    if (signedTx == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtSignTx error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

QString AccountsModulePlugin::extKeystoreSignTxWithPassphrase(const QString &address, const QString &passphrase, const QString &txJSON, const QString &chainIDHex)
{
    qDebug() << "AccountsModulePlugin::extKeystoreSignTxWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray txJsonUtf8 = txJSON.toUtf8();
    QByteArray chainIdHexUtf8 = chainIDHex.toUtf8();
    char* err = nullptr;
    char* signedTx = GoWSK_accounts_extkeystore_SignTxWithPassphrase(extkeystoreHandle, addressUtf8.data(), passphraseUtf8.data(), txJsonUtf8.data(), chainIdHexUtf8.data(), &err);
    if (signedTx == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtSignTxWithPassphrase error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(signedTx);
    GoWSK_FreeCString(signedTx);
    return result;
}

QString AccountsModulePlugin::extKeystoreDerive(const QString &address, const QString &derivationPath, int pin)
{
    qDebug() << "AccountsModulePlugin::extKeystoreDerive";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray derivationPathUtf8 = derivationPath.toUtf8();
    char* err = nullptr;
    char* derivedAddress = GoWSK_accounts_extkeystore_Derive(extkeystoreHandle, addressUtf8.data(), derivationPathUtf8.data(), pin, &err);
    if (derivedAddress == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtDerive error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

QString AccountsModulePlugin::extKeystoreDeriveWithPassphrase(const QString &address, const QString &derivationPath, int pin, const QString &passphrase, const QString &newPassphrase)
{
    qDebug() << "AccountsModulePlugin::extKeystoreDeriveWithPassphrase";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray derivationPathUtf8 = derivationPath.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    QByteArray newPassphraseUtf8 = newPassphrase.toUtf8();
    char* err = nullptr;
    char* derivedAddress = GoWSK_accounts_extkeystore_DeriveWithPassphrase(extkeystoreHandle, addressUtf8.data(), derivationPathUtf8.data(), pin, passphraseUtf8.data(), newPassphraseUtf8.data(), &err);
    if (derivedAddress == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtDeriveWithPassphrase error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(derivedAddress);
    GoWSK_FreeCString(derivedAddress);
    return result;
}

QString AccountsModulePlugin::extKeystoreFind(const QString &address, const QString &url)
{
    qDebug() << "AccountsModulePlugin::extKeystoreFind";
    if (extkeystoreHandle == 0) {
        qWarning() << "AccountsModulePlugin: Ext keystore not initialized";
        return QString();
    }
    QByteArray addressUtf8 = address.toUtf8();
    QByteArray urlUtf8 = url.toUtf8();
    char* err = nullptr;
    char* resultStr = GoWSK_accounts_extkeystore_Find(extkeystoreHandle, addressUtf8.data(), urlUtf8.data(), &err);
    if (resultStr == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtFind error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(resultStr);
    GoWSK_FreeCString(resultStr);
    return result;
}

// Key operations
QString AccountsModulePlugin::createExtKeyFromMnemonic(const QString &phrase, const QString &passphrase)
{
    qDebug() << "AccountsModulePlugin::createExtKeyFromMnemonic";
    QByteArray phraseUtf8 = phrase.toUtf8();
    QByteArray passphraseUtf8 = passphrase.toUtf8();
    char* err = nullptr;
    char* extKey = GoWSK_accounts_keys_CreateExtKeyFromMnemonic(phraseUtf8.data(), passphraseUtf8.data(), &err);
    if (extKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: CreateExtKeyFromMnemonic error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(extKey);
    GoWSK_FreeCString(extKey);
    return result;
}

QString AccountsModulePlugin::deriveExtKey(const QString &extKeyStr, const QString &pathStr)
{
    qDebug() << "AccountsModulePlugin::deriveExtKey";
    QByteArray extKeyStrUtf8 = extKeyStr.toUtf8();
    QByteArray pathStrUtf8 = pathStr.toUtf8();
    char* err = nullptr;
    char* derivedKey = GoWSK_accounts_keys_DeriveExtKey(extKeyStrUtf8.data(), pathStrUtf8.data(), &err);
    if (derivedKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: DeriveExtKey error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(derivedKey);
    GoWSK_FreeCString(derivedKey);
    return result;
}

QString AccountsModulePlugin::extKeyToECDSA(const QString &extKeyStr)
{
    qDebug() << "AccountsModulePlugin::extKeyToECDSA";
    QByteArray extKeyStrUtf8 = extKeyStr.toUtf8();
    char* err = nullptr;
    char* ecdsaKey = GoWSK_accounts_keys_ExtKeyToECDSA(extKeyStrUtf8.data(), &err);
    if (ecdsaKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ExtKeyToECDSA error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(ecdsaKey);
    GoWSK_FreeCString(ecdsaKey);
    return result;
}

QString AccountsModulePlugin::ecdsaToPublicKey(const QString &privateKeyECDSAStr)
{
    qDebug() << "AccountsModulePlugin::ecdsaToPublicKey";
    QByteArray privateKeyECDSAStrUtf8 = privateKeyECDSAStr.toUtf8();
    char* err = nullptr;
    char* publicKey = GoWSK_accounts_keys_ECDSAToPublicKey(privateKeyECDSAStrUtf8.data(), &err);
    if (publicKey == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: ECDSAToPublicKey error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(publicKey);
    GoWSK_FreeCString(publicKey);
    return result;
}

QString AccountsModulePlugin::publicKeyToAddress(const QString &publicKeyStr)
{
    qDebug() << "AccountsModulePlugin::publicKeyToAddress";
    QByteArray publicKeyStrUtf8 = publicKeyStr.toUtf8();
    char* err = nullptr;
    char* address = GoWSK_accounts_keys_PublicKeyToAddress(publicKeyStrUtf8.data(), &err);
    if (address == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: PublicKeyToAddress error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(address);
    GoWSK_FreeCString(address);
    return result;
}

// Mnemonic operations
QString AccountsModulePlugin::createRandomMnemonic(int length)
{
    qDebug() << "AccountsModulePlugin::createRandomMnemonic" << length;
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonic(length, &err);
    if (mnemonic == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: CreateRandomMnemonic error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

QString AccountsModulePlugin::createRandomMnemonicWithDefaultLength()
{
    qDebug() << "AccountsModulePlugin::createRandomMnemonicWithDefaultLength";
    char* err = nullptr;
    char* mnemonic = GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength(&err);
    if (mnemonic == nullptr) {
        QString emsg = err ? QString::fromUtf8(err) : QString("unknown error");
        if (err) GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: CreateRandomMnemonicWithDefaultLength error:" << emsg;
        return QString();
    }
    QString result = QString::fromUtf8(mnemonic);
    GoWSK_FreeCString(mnemonic);
    return result;
}

int AccountsModulePlugin::lengthToEntropyStrength(int length)
{
    qDebug() << "AccountsModulePlugin::lengthToEntropyStrength" << length;
    char* err = nullptr;
    uint32_t result = GoWSK_accounts_mnemonic_LengthToEntropyStrength(length, &err);
    if (err != nullptr) {
        QString emsg = QString::fromUtf8(err);
        GoWSK_FreeCString(err);
        qWarning() << "AccountsModulePlugin: LengthToEntropyStrength error:" << emsg;
        return 0;
    }
    return int(result);
}
