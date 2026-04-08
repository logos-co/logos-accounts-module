cmake_minimum_required(VERSION 3.14)
project(LogosAccountsModulePlugin LANGUAGES CXX)

# Include the Logos Module CMake helper
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

# Define the module (generated_code/ is picked up automatically by LogosModule.cmake)
logos_module(
    NAME accounts_module
    SOURCES
        src/accounts_module_impl.h
        src/accounts_module_impl.cpp
    FIND_PACKAGES
        Threads
    LINK_LIBRARIES
        Threads::Threads
)

# nlohmann/json — header-only, nix adds -isystem for buildInputs automatically

# Link Abseil if available
find_package(absl QUIET)
if(absl_FOUND)
    target_link_libraries(accounts_module_module_plugin PRIVATE
        absl::base absl::strings absl::log absl::check)
endif()
