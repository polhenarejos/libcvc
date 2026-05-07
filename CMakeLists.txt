#/*
# * This file is part of the libcvc distribution (https://github.com/polhenarejos/libcvc).
# * Copyright (c) 2026 Pol Henarejos.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU Affero General Public License as published by
# * the Free Software Foundation, version 3.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# * Affero General Public License for more details.
# *
# * You should have received a copy of the GNU Affero General Public License
# * along with this program. If not, see <https://www.gnu.org/licenses/>.
# */

cmake_minimum_required(VERSION 3.13)

project(libcvc C)

option(LIBCVC_USE_FIND_PACKAGE_MBEDTLS "Use find_package(MbedTLS/mbedtls) first" ON)
option(LIBCVC_BUILD_TESTS "Build libcvc tests" OFF)
set(MBEDTLS_INCLUDE_DIR "" CACHE PATH "Path to mbedTLS include directory (contains mbedtls/pk.h)")
set(_libcvc_test_mbedtls_libs "")

add_library(cvc
    src/cvc_tlv.c
    src/cvc_parse.c
    src/cvc_build.c
    src/cvc_sign.c
    src/cvc_write.c
)

target_include_directories(cvc
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
)

set(_libcvc_mbedtls_linked FALSE)

if(LIBCVC_USE_FIND_PACKAGE_MBEDTLS)
    find_package(MbedTLS QUIET)
    if(TARGET MbedTLS::mbedtls)
        target_link_libraries(cvc PRIVATE MbedTLS::mbedtls)
        list(APPEND _libcvc_test_mbedtls_libs MbedTLS::mbedtls)
        set(_libcvc_mbedtls_linked TRUE)
    endif()

    if(NOT _libcvc_mbedtls_linked)
        find_package(mbedTLS QUIET)
        if(TARGET mbedTLS::mbedtls)
            target_link_libraries(cvc PRIVATE mbedTLS::mbedtls)
            list(APPEND _libcvc_test_mbedtls_libs mbedTLS::mbedtls)
            set(_libcvc_mbedtls_linked TRUE)
        endif()
    endif()
endif()

if(NOT _libcvc_mbedtls_linked)
    if(MBEDTLS_INCLUDE_DIR)
        if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/pk.h")
            target_include_directories(cvc PUBLIC "${MBEDTLS_INCLUDE_DIR}")
            if(DEFINED MBEDTLS_LIBRARIES AND MBEDTLS_LIBRARIES)
                target_link_libraries(cvc PRIVATE ${MBEDTLS_LIBRARIES})
                list(APPEND _libcvc_test_mbedtls_libs ${MBEDTLS_LIBRARIES})
                set(_libcvc_mbedtls_linked TRUE)
            else()
                list(APPEND _libcvc_test_mbedtls_libs mbedtls mbedx509 mbedcrypto)
            endif()
        else()
            message(FATAL_ERROR "MBEDTLS_INCLUDE_DIR does not contain mbedtls/pk.h: ${MBEDTLS_INCLUDE_DIR}")
        endif()
    elseif(TARGET mbedtls)
        target_link_libraries(cvc PRIVATE mbedtls)
        list(APPEND _libcvc_test_mbedtls_libs mbedtls)
        set(_libcvc_mbedtls_linked TRUE)
    elseif(TARGET mbedcrypto)
        target_link_libraries(cvc PRIVATE mbedcrypto)
        list(APPEND _libcvc_test_mbedtls_libs mbedcrypto)
        set(_libcvc_mbedtls_linked TRUE)
    else()
        message(FATAL_ERROR
            "mbedTLS not found. Either:\\n"
            "  1) provide a package so find_package can locate it,\\n"
            "  2) define target 'mbedtls' or 'mbedcrypto' before adding libcvc, or\\n"
            "  3) set -DMBEDTLS_INCLUDE_DIR=/path/to/mbedtls/include"
            " and optionally -DMBEDTLS_LIBRARIES=mbedcrypto;mbedtls")
    endif()
endif()

set_target_properties(cvc PROPERTIES
    OUTPUT_NAME cvc
    POSITION_INDEPENDENT_CODE ON
)

if(LIBCVC_BUILD_TESTS)
    enable_testing()

    add_executable(libcvc_tests
        tests/test_libcvc.c
    )
    target_include_directories(libcvc_tests PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src)
    target_compile_definitions(libcvc_tests PRIVATE
        LIBCVC_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")
    target_link_libraries(libcvc_tests PRIVATE cvc)
    if(_libcvc_test_mbedtls_libs)
        target_link_libraries(libcvc_tests PRIVATE ${_libcvc_test_mbedtls_libs})
    endif()
    add_test(NAME libcvc_tests COMMAND libcvc_tests)

    add_executable(libcvc_gen_cert
        tools/gen_cert_libcvc.c
    )
    target_link_libraries(libcvc_gen_cert PRIVATE cvc)
    if(_libcvc_test_mbedtls_libs)
        target_link_libraries(libcvc_gen_cert PRIVATE ${_libcvc_test_mbedtls_libs})
    endif()

    add_executable(libcvc_gen_weierstrass
        tools/gen_weierstrass_variants.c
    )
    target_link_libraries(libcvc_gen_weierstrass PRIVATE cvc)
    if(_libcvc_test_mbedtls_libs)
        target_link_libraries(libcvc_gen_weierstrass PRIVATE ${_libcvc_test_mbedtls_libs})
    endif()
endif()
