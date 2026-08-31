# doctest v2.4.11 declares an older CMake minimum; CMake 4 requires an
# explicit policy floor for vendored projects that still build cleanly.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# Prefer a doctest already on the system. A sandboxed build has no network, so
# fetching it from GitHub is what forced the packaged build to skip its tests
# and report a compile as a pass. With the package supplied the suite runs
# where the port is built. The fetch stays as the fallback for a working tree
# that has no doctest installed.
find_package(doctest QUIET)
if(doctest_FOUND)
    get_target_property(UNICODE_CPP_DOCTEST_INCLUDE
        doctest::doctest INTERFACE_INCLUDE_DIRECTORIES)
    find_path(UNICODE_CPP_DOCTEST_CMAKE_DIR doctest.cmake
        PATHS
            "${doctest_DIR}"
            "${UNICODE_CPP_DOCTEST_INCLUDE}/../lib/cmake/doctest"
            "${UNICODE_CPP_DOCTEST_INCLUDE}/../share/doctest/cmake"
        NO_DEFAULT_PATH)
else()
    include(FetchContent)
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.4.11)
    FetchContent_MakeAvailable(doctest)
    set(UNICODE_CPP_DOCTEST_CMAKE_DIR "${doctest_SOURCE_DIR}/scripts/cmake")
endif()

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
    hash_input_stability_test.cpp
    ai_watermark_detectability_test.cpp
    emoji_zwj_integrity_test.cpp
    locale_case_inversion_test.cpp
    case_expansion_mismatch_test.cpp
    normalization_bomb_test.cpp
    nfc_idempotence_witness_test.cpp
    stream_safe_violation_test.cpp
    surrogate_reassembly_test.cpp
    renderer_divergence_test.cpp
    filename_disguise_test.cpp
    source_display_divergence_test.cpp
    skin_tone_variation_forgery_test.cpp
    identifier_form_drift_test.cpp
    admissibility_form_drift_test.cpp)
target_link_libraries(unicode_cpp_tests
    PRIVATE unicode_cpp::unicode_cpp doctest::doctest)

if(UNICODE_CPP_DOCTEST_CMAKE_DIR)
    include(${UNICODE_CPP_DOCTEST_CMAKE_DIR}/doctest.cmake)
    doctest_discover_tests(unicode_cpp_tests)
else()
    # No discovery script alongside the package: register the binary as one
    # test so ctest still runs the whole suite.
    add_test(NAME unicode_cpp_tests COMMAND unicode_cpp_tests)
endif()
