include_guard()

include(CheckIPOSupported)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)

function(project_configure_lto)
    set(${PROJECT_NAME}_LTO_MODE "AUTO" CACHE STRING "LTO mode: AUTO (Release only), ON, or OFF")
    set_property(CACHE ${PROJECT_NAME}_LTO_MODE PROPERTY STRINGS "AUTO" "ON" "OFF")

    string(TOUPPER "${${PROJECT_NAME}_LTO_MODE}" _hazel_lto_mode)
    if(
        NOT _hazel_lto_mode STREQUAL "AUTO"
        AND NOT _hazel_lto_mode STREQUAL "ON"
        AND NOT _hazel_lto_mode STREQUAL "OFF"
    )
        message(
            FATAL_ERROR
            "Unsupported ${PROJECT_NAME}_LTO_MODE='${${PROJECT_NAME}_LTO_MODE}'. Use AUTO, ON, or OFF."
        )
    endif()

    set(_hazel_enable_lto OFF)
    if(_hazel_lto_mode STREQUAL "ON")
        set(_hazel_enable_lto ON)
    elseif(_hazel_lto_mode STREQUAL "AUTO" AND CMAKE_BUILD_TYPE STREQUAL "Release")
        set(_hazel_enable_lto ON)
    endif()

    if(NOT _hazel_enable_lto)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF PARENT_SCOPE)
        message(
            STATUS
            "LTO disabled (${PROJECT_NAME}_LTO_MODE=${_hazel_lto_mode}, build type='${CMAKE_BUILD_TYPE}')."
        )
        return()
    endif()

    check_ipo_supported(RESULT _hazel_ipo_supported OUTPUT _hazel_ipo_output LANGUAGES C CXX)
    if(_hazel_ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON PARENT_SCOPE)
        message(STATUS "LTO enabled for Release builds via IPO support.")
        return()
    endif()

    if(CMAKE_C_COMPILER_ID MATCHES ".*Clang")
        set(_hazel_manual_lto_flag "-flto=thin")
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(_hazel_manual_lto_flag "-flto")
    else()
        if(_hazel_lto_mode STREQUAL "ON")
            message(
                FATAL_ERROR
                "LTO was explicitly requested but compiler family '${CMAKE_C_COMPILER_ID}' has no manual fallback configured."
            )
        endif()

        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF PARENT_SCOPE)
        message(
            STATUS
            "LTO requested automatically for Release, but compiler family '${CMAKE_C_COMPILER_ID}' has no manual fallback configured."
        )
        return()
    endif()

    check_c_compiler_flag("${_hazel_manual_lto_flag}" _hazel_manual_lto_c_supported)
    check_cxx_compiler_flag("${_hazel_manual_lto_flag}" _hazel_manual_lto_cxx_supported)
    check_linker_flag(C "${_hazel_manual_lto_flag}" _hazel_manual_lto_link_supported)

    if(
        _hazel_manual_lto_c_supported
        AND _hazel_manual_lto_cxx_supported
        AND _hazel_manual_lto_link_supported
    )
        set(_hazel_cx_flags "${${PROJECT_NAME}_CX_FLAGS}")
        set(_hazel_link_flags "${${PROJECT_NAME}_LINK_FLAGS}")
        list(APPEND _hazel_cx_flags "${_hazel_manual_lto_flag}")
        list(APPEND _hazel_link_flags "${_hazel_manual_lto_flag}")
        list(REMOVE_DUPLICATES _hazel_cx_flags)
        list(REMOVE_DUPLICATES _hazel_link_flags)

        set(${PROJECT_NAME}_CX_FLAGS "${_hazel_cx_flags}" PARENT_SCOPE)
        set(${PROJECT_NAME}_LINK_FLAGS "${_hazel_link_flags}" PARENT_SCOPE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF PARENT_SCOPE)
        message(
            STATUS
            "LTO enabled for Release via manual fallback flag '${_hazel_manual_lto_flag}' (IPO unavailable)."
        )
    elseif(_hazel_lto_mode STREQUAL "ON")
        message(
            FATAL_ERROR
            "LTO was explicitly requested, but IPO is unavailable and manual fallback flag '${_hazel_manual_lto_flag}' is unsupported. IPO error: ${_hazel_ipo_output}"
        )
    else()
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF PARENT_SCOPE)
        message(
            STATUS
            "LTO requested automatically for Release, but IPO and manual fallback are unavailable. IPO error: ${_hazel_ipo_output}"
        )
    endif()
endfunction()
