include(FetchContent)

# doctest v2.4.11 declares an older CMake minimum; CMake 4 requires an
# explicit policy floor for vendored projects that still build cleanly.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11)
FetchContent_MakeAvailable(doctest)

add_executable(unicode_cpp_tests
    utf8_test.cpp
    utf16_test.cpp
    utf32_test.cpp
    bom_test.cpp
    noncharacters_test.cpp
    identifier_test.cpp
    segmentation_test.cpp
    opaque_blob_test.cpp
    validated_utf8_test.cpp
    security_test.cpp
    nfkc_nfkd_test.cpp
    casing_test.cpp
    bip39_test.cpp
    locale_case_inversion_test.cpp
    normalization_bomb_test.cpp
    surrogate_reassembly_test.cpp)
target_link_libraries(unicode_cpp_tests
    PRIVATE unicode_cpp::unicode_cpp doctest::doctest)

include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
doctest_discover_tests(unicode_cpp_tests)
