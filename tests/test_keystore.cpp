// Unit tests for AccountsModuleImpl — keystore, extended keystore, keys, mnemonic.
// All Go Wallet SDK calls are mocked at link time via mock_gowalletsdk.cpp.

#include <logos_test.h>
#include "accounts_module_impl.h"

// ── Keystore: init / close ──────────────────────────────────────────────────

LOGOS_TEST(initKeystore_returns_true_on_success) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    LOGOS_ASSERT_TRUE(impl.initKeystore("/tmp/ks", 4096, 6));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_NewKeyStore"));
}

LOGOS_TEST(initKeystore_returns_false_when_handle_is_zero) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(0);

    AccountsModuleImpl impl;
    LOGOS_ASSERT_FALSE(impl.initKeystore("/tmp/ks", 4096, 6));
}

LOGOS_TEST(closeKeystore_returns_true_after_init) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.closeKeystore(""));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_CloseKeyStore"));
}

LOGOS_TEST(closeKeystore_returns_false_without_init) {
    auto t = LogosTestContext("accounts_module");
    AccountsModuleImpl impl;
    LOGOS_ASSERT_FALSE(impl.closeKeystore(""));
}

// ── Keystore: accounts ──────────────────────────────────────────────────────

LOGOS_TEST(keystoreAccounts_returns_empty_for_empty_array) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_Accounts").returns("[]");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    auto accts = impl.keystoreAccounts();
    LOGOS_ASSERT_EQ(static_cast<int>(accts.size()), 0);
}

LOGOS_TEST(keystoreAccounts_returns_empty_without_init) {
    auto t = LogosTestContext("accounts_module");
    AccountsModuleImpl impl;
    auto accts = impl.keystoreAccounts();
    LOGOS_ASSERT_EQ(static_cast<int>(accts.size()), 0);
}

LOGOS_TEST(keystoreAccounts_parses_account_objects) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_Accounts")
        .returns("[{\"address\":\"0xABC\"},{\"address\":\"0xDEF\"}]");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    auto accts = impl.keystoreAccounts();
    LOGOS_ASSERT_EQ(static_cast<int>(accts.size()), 2);
}

// ── Keystore: new account / import / export ─────────────────────────────────

LOGOS_TEST(keystoreNewAccount_returns_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_NewAccount").returns("0xABCD1234");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string addr = impl.keystoreNewAccount("pass");
    LOGOS_ASSERT_EQ(addr, std::string("0xABCD1234"));
}

LOGOS_TEST(keystoreNewAccount_empty_without_init) {
    auto t = LogosTestContext("accounts_module");
    AccountsModuleImpl impl;
    LOGOS_ASSERT_TRUE(impl.keystoreNewAccount("pass").empty());
}

LOGOS_TEST(keystoreImport_returns_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_Import").returns("0x1111");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string addr = impl.keystoreImport("{\"key\":\"data\"}", "old", "new");
    LOGOS_ASSERT_EQ(addr, std::string("0x1111"));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_Import"));
}

LOGOS_TEST(keystoreExport_returns_key_json) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_Export").returns("{\"key\":\"exported\"}");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string keyJson = impl.keystoreExport("0xABC", "pass", "newpass");
    LOGOS_ASSERT_EQ(keyJson, std::string("{\"key\":\"exported\"}"));
}

// ── Keystore: delete / hasAddress ───────────────────────────────────────────

LOGOS_TEST(keystoreDelete_returns_true) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.keystoreDelete("0xABC", "pass"));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_Delete"));
}

LOGOS_TEST(keystoreHasAddress_returns_true_when_found) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_HasAddress").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.keystoreHasAddress("0xABC"));
}

LOGOS_TEST(keystoreHasAddress_returns_false_when_not_found) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_HasAddress").returns(0);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_FALSE(impl.keystoreHasAddress("0xABC"));
}

// ── Keystore: lock / unlock ─────────────────────────────────────────────────

LOGOS_TEST(keystoreUnlock_calls_sdk) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.keystoreUnlock("0xABC", "pass"));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_Unlock"));
}

LOGOS_TEST(keystoreLock_calls_sdk) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.keystoreLock("0xABC"));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_Lock"));
}

LOGOS_TEST(keystoreTimedUnlock_calls_sdk) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.keystoreTimedUnlock("0xABC", "pass", 60));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keystore_TimedUnlock"));
}

// ── Keystore: signing ───────────────────────────────────────────────────────

LOGOS_TEST(keystoreSignHash_returns_signature) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_SignHash").returns("0xSIG123");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string sig = impl.keystoreSignHash("0xABC", "0xHASH");
    LOGOS_ASSERT_EQ(sig, std::string("0xSIG123"));
}

LOGOS_TEST(keystoreSignTx_returns_signed_tx) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_SignTx").returns("0xSIGNED_TX");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string tx = impl.keystoreSignTx("0xABC", "{\"tx\":1}", "0x1");
    LOGOS_ASSERT_EQ(tx, std::string("0xSIGNED_TX"));
}

LOGOS_TEST(keystoreImportECDSA_returns_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_keystore_ImportECDSA").returns("0xECDSA_ADDR");

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    std::string addr = impl.keystoreImportECDSA("0xPRIVKEY", "pass");
    LOGOS_ASSERT_EQ(addr, std::string("0xECDSA_ADDR"));
}

// ── Extended Keystore ───────────────────────────────────────────────────────

LOGOS_TEST(initExtKeystore_returns_true_on_success) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_extkeystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    LOGOS_ASSERT_TRUE(impl.initExtKeystore("/tmp/ext-ks", 4096, 6));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_extkeystore_NewKeyStore"));
}

LOGOS_TEST(extKeystoreNewAccount_returns_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_extkeystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_extkeystore_NewAccount").returns("0xEXT_ADDR");

    AccountsModuleImpl impl;
    impl.initExtKeystore("/tmp/ext-ks", 4096, 6);
    std::string addr = impl.extKeystoreNewAccount("pass");
    LOGOS_ASSERT_EQ(addr, std::string("0xEXT_ADDR"));
}

LOGOS_TEST(extKeystoreHasAddress_returns_true) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_extkeystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_extkeystore_HasAddress").returns(1);

    AccountsModuleImpl impl;
    impl.initExtKeystore("/tmp/ext-ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.extKeystoreHasAddress("0xABC"));
}

LOGOS_TEST(extKeystoreDerive_returns_derived_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_extkeystore_NewKeyStore").returns(1);
    t.mockCFunction("GoWSK_accounts_extkeystore_Derive").returns("0xDERIVED");

    AccountsModuleImpl impl;
    impl.initExtKeystore("/tmp/ext-ks", 4096, 6);
    std::string addr = impl.extKeystoreDerive("0xABC", "m/44'/60'/0'/0/0", 0);
    LOGOS_ASSERT_EQ(addr, std::string("0xDERIVED"));
}

LOGOS_TEST(closeExtKeystore_returns_true_after_init) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_extkeystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initExtKeystore("/tmp/ext-ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.closeExtKeystore());
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_extkeystore_CloseKeyStore"));
}

// ── Key Operations ──────────────────────────────────────────────────────────

LOGOS_TEST(createExtKeyFromMnemonic_returns_key) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keys_CreateExtKeyFromMnemonic")
        .returns("xprv9s21ZrQH143K...");

    AccountsModuleImpl impl;
    std::string key = impl.createExtKeyFromMnemonic("word1 word2 word3", "pass");
    LOGOS_ASSERT_EQ(key, std::string("xprv9s21ZrQH143K..."));
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_keys_CreateExtKeyFromMnemonic"));
}

LOGOS_TEST(deriveExtKey_returns_derived_key) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keys_DeriveExtKey").returns("xprv_derived...");

    AccountsModuleImpl impl;
    std::string key = impl.deriveExtKey("xprv_root...", "m/44'/60'/0'");
    LOGOS_ASSERT_EQ(key, std::string("xprv_derived..."));
}

LOGOS_TEST(extKeyToECDSA_returns_ecdsa_key) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keys_ExtKeyToECDSA").returns("0xECDSA_PRIV");

    AccountsModuleImpl impl;
    std::string key = impl.extKeyToECDSA("xprv_key...");
    LOGOS_ASSERT_EQ(key, std::string("0xECDSA_PRIV"));
}

LOGOS_TEST(ecdsaToPublicKey_returns_public_key) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keys_ECDSAToPublicKey").returns("0xPUBKEY");

    AccountsModuleImpl impl;
    std::string pub = impl.ecdsaToPublicKey("0xECDSA_PRIV");
    LOGOS_ASSERT_EQ(pub, std::string("0xPUBKEY"));
}

LOGOS_TEST(publicKeyToAddress_returns_address) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keys_PublicKeyToAddress").returns("0xADDRESS");

    AccountsModuleImpl impl;
    std::string addr = impl.publicKeyToAddress("0xPUBKEY");
    LOGOS_ASSERT_EQ(addr, std::string("0xADDRESS"));
}

// ── Mnemonic Operations ─────────────────────────────────────────────────────

LOGOS_TEST(createRandomMnemonic_returns_words) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_mnemonic_CreateRandomMnemonic")
        .returns("word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12");

    AccountsModuleImpl impl;
    std::string mnemonic = impl.createRandomMnemonic(12);
    LOGOS_ASSERT_FALSE(mnemonic.empty());
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_mnemonic_CreateRandomMnemonic"));
}

LOGOS_TEST(createRandomMnemonicWithDefaultLength_returns_words) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength")
        .returns("default length mnemonic phrase words go here in a row now done with twelve");

    AccountsModuleImpl impl;
    std::string mnemonic = impl.createRandomMnemonicWithDefaultLength();
    LOGOS_ASSERT_FALSE(mnemonic.empty());
    LOGOS_ASSERT(t.cFunctionCalled("GoWSK_accounts_mnemonic_CreateRandomMnemonicWithDefaultLength"));
}

LOGOS_TEST(lengthToEntropyStrength_returns_128_for_12_words) {
    auto t = LogosTestContext("accounts_module");
    uint32_t expected = 128;
    t.mockCFunction("GoWSK_accounts_mnemonic_LengthToEntropyStrength")
        .returnsRaw(&expected, sizeof(expected));

    AccountsModuleImpl impl;
    int64_t strength = impl.lengthToEntropyStrength(12);
    LOGOS_ASSERT_EQ(static_cast<int>(strength), 128);
}

// ── Edge cases ──────────────────────────────────────────────────────────────

LOGOS_TEST(keystore_operations_fail_without_init) {
    auto t = LogosTestContext("accounts_module");
    AccountsModuleImpl impl;

    LOGOS_ASSERT_TRUE(impl.keystoreNewAccount("pass").empty());
    LOGOS_ASSERT_TRUE(impl.keystoreImport("{}", "a", "b").empty());
    LOGOS_ASSERT_TRUE(impl.keystoreExport("0x", "a", "b").empty());
    LOGOS_ASSERT_FALSE(impl.keystoreDelete("0x", "pass"));
    LOGOS_ASSERT_FALSE(impl.keystoreHasAddress("0x"));
    LOGOS_ASSERT_FALSE(impl.keystoreUnlock("0x", "pass"));
    LOGOS_ASSERT_FALSE(impl.keystoreLock("0x"));
    LOGOS_ASSERT_TRUE(impl.keystoreSignHash("0x", "0x").empty());
}

LOGOS_TEST(ext_keystore_operations_fail_without_init) {
    auto t = LogosTestContext("accounts_module");
    AccountsModuleImpl impl;

    LOGOS_ASSERT_TRUE(impl.extKeystoreNewAccount("pass").empty());
    LOGOS_ASSERT_FALSE(impl.extKeystoreHasAddress("0x"));
    LOGOS_ASSERT_FALSE(impl.extKeystoreUnlock("0x", "pass"));
    LOGOS_ASSERT_FALSE(impl.extKeystoreLock("0x"));
    LOGOS_ASSERT_TRUE(impl.extKeystoreSignHash("0x", "0x").empty());
    LOGOS_ASSERT_TRUE(impl.extKeystoreDerive("0x", "m/0", 0).empty());
    LOGOS_ASSERT_FALSE(impl.closeExtKeystore());
}
