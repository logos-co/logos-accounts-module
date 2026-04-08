cmake_minimum_required(VERSION 3.14)
project(AccountsModuleTests LANGUAGES CXX)

include(LogosTest)

logos_test(
    NAME accounts_module_tests
    MODULE_SOURCES
        ../src/accounts_module_impl.cpp
    TEST_SOURCES
        main.cpp
        test_keystore.cpp
    MOCK_C_SOURCES
        mocks/mock_gowalletsdk.cpp
    EXTRA_INCLUDES
        stubs
)
