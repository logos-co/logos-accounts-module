cmake_minimum_required(VERSION 3.14)
project(LogosAccountsModulePlugin LANGUAGES CXX)

# Include the Logos Module CMake helper
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

# Ensure metadata.json is in the build directory so AUTOMOC embeds it
# (Q_PLUGIN_METADATA FILE "metadata.json" resolves relative to the header in src/)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

# Define the module
logos_module(
    NAME accounts_module
    SOURCES
        src/accounts_module_impl.h
        src/accounts_module_impl.cpp
        generated_code/accounts_module_qt_glue.h
        generated_code/accounts_module_dispatch.cpp
    FIND_PACKAGES
        Threads
    LINK_LIBRARIES
        Threads::Threads
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/generated_code
)

# go-wallet-sdk static library (requires whole-archive for Go runtime initialization)
find_library(LIBGOWALLETSDK
    NAMES libgowalletsdk.a libgowalletsdk.lib
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib
    NO_DEFAULT_PATH
)

if(LIBGOWALLETSDK)
    target_link_libraries(accounts_module_module_plugin PRIVATE ${LIBGOWALLETSDK})
    if(APPLE)
        target_link_options(accounts_module_module_plugin PRIVATE -Wl,-force_load ${LIBGOWALLETSDK})
        target_link_libraries(accounts_module_module_plugin PUBLIC "-framework CoreFoundation")
        target_link_libraries(accounts_module_module_plugin PUBLIC "-framework Security")
    else()
        target_link_options(accounts_module_module_plugin PRIVATE
            -Wl,--whole-archive ${LIBGOWALLETSDK} -Wl,--no-whole-archive)
    endif()
endif()

# Link Abseil if available
find_package(absl QUIET)
if(absl_FOUND)
    target_link_libraries(accounts_module_module_plugin PRIVATE
        absl::base absl::strings absl::log absl::check)
endif()
