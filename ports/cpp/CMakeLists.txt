cmake_minimum_required(VERSION 3.20)

project(unicode_cpp
    VERSION 0.1.0
    DESCRIPTION
        "Strict Unicode-as-attack-surface conformance for C++"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(unicode_cpp INTERFACE)
add_library(unicode_cpp::unicode_cpp ALIAS unicode_cpp)

target_include_directories(unicode_cpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_compile_features(unicode_cpp INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(unicode_cpp INTERFACE /W4 /WX /permissive-)
else()
    target_compile_options(unicode_cpp INTERFACE
        -Wall -Wextra -Wpedantic -Werror)
endif()

option(UNICODE_CPP_BUILD_TESTS "Build unicode_cpp tests" OFF)
if(UNICODE_CPP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

include(GNUInstallDirs)
install(DIRECTORY include/unicode_cpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

foreach(UNICODE_CPP_DATA_FILE IN ITEMS
    CaseFolding.txt
    CompositionExclusions.txt
    DerivedBidiClass.txt
    DerivedCoreProperties.txt
    DerivedJoiningType.txt
    EastAsianWidth.txt
    emoji-data.txt
    emoji-zwj-sequences.txt
    IdentifierStatus.txt
    KnownAttackTargets.txt
    PropertyValueAliases.txt
    ScriptExtensions.txt
    Scripts.txt
    SpecialCasing.txt
    UnicodeData.txt
    confusables.txt)
    file(REAL_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/data/${UNICODE_CPP_DATA_FILE}"
        UNICODE_CPP_DATA_REAL)
    install(FILES "${UNICODE_CPP_DATA_REAL}"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/unicode_cpp/data
        RENAME "${UNICODE_CPP_DATA_FILE}")
endforeach()

# BIP-39 wordlists (bip39-canonical) ship as a subdirectory of the data dir.
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/data/bip39"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/unicode_cpp/data
    FILES_MATCHING PATTERN "*.txt")
