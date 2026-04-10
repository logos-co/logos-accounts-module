// Integration tests for AccountsModuleImpl — uses the REAL libgowalletsdk static library.
// No mocking. Exercises keystore and mnemonic bindings end-to-end.
//
// Requires libgowalletsdk.a (and CGo header) in ../lib at build time.
// Skipped automatically when the archive is not found (see CMakeLists.txt).

#include <logos_test.h>
#include "accounts_module_impl.h"

#include <QDir>
#include <QTemporaryDir>

#include <string>

LOGOS_TEST(integration_keystore_new_account) {
    QTemporaryDir dir(QDir::tempPath() + "/logos-accounts-integration-XXXXXX");
    LOGOS_ASSERT_TRUE(dir.isValid());

    const std::string ksDir = dir.path().toStdString();
    AccountsModuleImpl impl;
    LOGOS_ASSERT_TRUE(impl.initKeystore(ksDir, 4096, 6));

    const std::string addr = impl.keystoreNewAccount("integration-test-passphrase");
    LOGOS_ASSERT_FALSE(addr.empty());

    const auto accounts = impl.keystoreAccounts();
    LOGOS_ASSERT_EQ(static_cast<int>(accounts.size()), 1);
    LOGOS_ASSERT_FALSE(accounts[0].empty());
    LOGOS_ASSERT_TRUE(accounts[0].find(addr) != std::string::npos);
}

LOGOS_TEST(integration_mnemonic_default_length) {
    AccountsModuleImpl impl;
    const std::string phrase = impl.createRandomMnemonicWithDefaultLength();
    LOGOS_ASSERT_FALSE(phrase.empty());
    LOGOS_ASSERT_TRUE(phrase.find(' ') != std::string::npos);
}
