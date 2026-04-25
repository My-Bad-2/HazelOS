include_guard()

function(_hazel_normalize_compiler_id in_id out_var)
    if("${in_id}" STREQUAL "AppleClang")
        set(${out_var} "Clang" PARENT_SCOPE)
    else()
        set(${out_var} "${in_id}" PARENT_SCOPE)
    endif()
endfunction()

function(project_validate_compiler_support)
    if(NOT CMAKE_C_COMPILER_ID OR NOT CMAKE_CXX_COMPILER_ID)
        message(FATAL_ERROR "Both C and CXX compilers must be configured before validation.")
    endif()

    _hazel_normalize_compiler_id("${CMAKE_C_COMPILER_ID}" _hazel_c_compiler_id)
    _hazel_normalize_compiler_id("${CMAKE_CXX_COMPILER_ID}" _hazel_cxx_compiler_id)

    set(_hazel_supported_compilers "GNU" "Clang")

    list(FIND _hazel_supported_compilers "${_hazel_c_compiler_id}" _hazel_c_supported_idx)
    if(_hazel_c_supported_idx EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported C compiler '${CMAKE_C_COMPILER_ID}'. Supported compiler families are GCC and Clang."
        )
    endif()

    list(FIND _hazel_supported_compilers "${_hazel_cxx_compiler_id}" _hazel_cxx_supported_idx)
    if(_hazel_cxx_supported_idx EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported CXX compiler '${CMAKE_CXX_COMPILER_ID}'. Supported compiler families are GCC and Clang."
        )
    endif()

    if(NOT _hazel_c_compiler_id STREQUAL _hazel_cxx_compiler_id)
        message(
            FATAL_ERROR
            "C and CXX compilers must come from the same family. Detected C='${CMAKE_C_COMPILER_ID}' and CXX='${CMAKE_CXX_COMPILER_ID}'."
        )
    endif()

    if(_hazel_c_compiler_id STREQUAL "GNU")
        set(_hazel_compiler_family "gcc")
    else()
        set(_hazel_compiler_family "clang")
    endif()

    set(${PROJECT_NAME}_COMPILER_FAMILY
        "${_hazel_compiler_family}"
        CACHE STRING
        "Compiler family used by the build"
        FORCE
    )
    set_property(CACHE ${PROJECT_NAME}_COMPILER_FAMILY PROPERTY STRINGS "gcc" "clang")

    message(STATUS "Compiler family: ${${PROJECT_NAME}_COMPILER_FAMILY}")
    message(
        STATUS
        "C compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} (${CMAKE_C_COMPILER})"
    )
    message(
        STATUS
        "CXX compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} (${CMAKE_CXX_COMPILER})"
    )
endfunction()
