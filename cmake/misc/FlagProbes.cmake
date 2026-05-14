include_guard()

include(CheckLinkerFlag)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakeParseArguments)

function(hazel_check_link_driver_flag)
    set(oneValueArgs LANG FLAG OUT_VAR)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "" ${ARGN})

    if(NOT ARG_LANG)
        message(FATAL_ERROR "hazel_check_link_driver_flag: LANG argument is required.")
    endif()
    if(NOT ARG_FLAG)
        message(FATAL_ERROR "hazel_check_link_driver_flag: FLAG argument is required.")
    endif()
    if(NOT ARG_OUT_VAR)
        message(FATAL_ERROR "hazel_check_link_driver_flag: OUT_VAR argument is required.")
    endif()

    if(NOT ARG_LANG STREQUAL "C" AND NOT ARG_LANG STREQUAL "CXX")
        message(
            FATAL_ERROR
            "hazel_check_link_driver_flag: Unsupported LANG '${ARG_LANG}'. Use C or CXX."
        )
    endif()

    string(REGEX REPLACE "[^a-zA-Z0-9_+=.-]" "_" _hazel_safe_flag_name "${ARG_FLAG}")
    set(_hazel_cache_var "HAZEL_LINK_DRIVER_FLAG_${ARG_LANG}_${_hazel_safe_flag_name}")

    if(NOT DEFINED ${_hazel_cache_var})
        check_linker_flag(${ARG_LANG} "${ARG_FLAG}" _hazel_link_supported)
        if(_hazel_link_supported)
            set(${_hazel_cache_var} ON CACHE INTERNAL "Linker driver flag probe result" FORCE)
        else()
            # Fallback for cross/try-compile configurations where linker probes are unreliable.
            if(ARG_LANG STREQUAL "C")
                check_c_compiler_flag("${ARG_FLAG}" _hazel_driver_supported)
            else()
                check_cxx_compiler_flag("${ARG_FLAG}" _hazel_driver_supported)
            endif()

            set(${_hazel_cache_var}
                ${_hazel_driver_supported}
                CACHE INTERNAL
                "Linker driver flag probe result"
                FORCE
            )
        endif()
    endif()

    set(${ARG_OUT_VAR} ${${_hazel_cache_var}} PARENT_SCOPE)
endfunction()
