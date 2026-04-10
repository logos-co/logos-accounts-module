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

logos_find_go_static_archive(GOWALLETSDK_LIB gowalletsdk)
if(GOWALLETSDK_LIB)
    message(STATUS "[AccountsTests] libgowalletsdk found — building integration tests")
    logos_test(
        NAME accounts_module_integration_tests
        MODULE_SOURCES
            ../src/accounts_module_impl.cpp
        TEST_SOURCES
            main.cpp
            test_accounts_integration.cpp
        EXTRA_INCLUDES
            ../lib
        LINK_GO_STATIC_ARCHIVE
            ${GOWALLETSDK_LIB}
    )
else()
    message(STATUS "[AccountsTests] libgowalletsdk not found in ../lib — skipping integration tests")
endif()
