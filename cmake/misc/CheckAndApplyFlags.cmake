include_guard()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakeParseArguments)
include("${CMAKE_CURRENT_LIST_DIR}/FlagProbes.cmake")

function(target_apply_linker_settings)
    set(options "")
    set(oneValueArgs TARGET SCRIPT SCOPE)
    set(multiValueArgs FLAGS LANG)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "target_apply_linker_settings: TARGET argument is required.")
    endif()
    if(NOT TARGET ${ARG_TARGET})
        message(FATAL_ERROR "target_apply_linker_settings: Target '${ARG_TARGET}' does not exist.")
    endif()
    if(NOT ARG_LANG)
        set(ARG_LANG "C")
    endif()
    if(NOT ARG_SCOPE)
        set(ARG_SCOPE "PRIVATE")
    endif()

    foreach(FLAG IN LISTS ARG_FLAGS)
        set(_hazel_supported_for_any_lang OFF)

        string(REGEX REPLACE "[^a-zA-Z0-9_+=.-]" "_" _hazel_safe_flag_name "${FLAG}")
        foreach(_hazel_lang IN LISTS ARG_LANG)
            set(_hazel_check_var "LINKER_SUPPORTS_${_hazel_lang}_${_hazel_safe_flag_name}")
            if(NOT DEFINED ${_hazel_check_var})
                hazel_check_link_driver_flag(
                    LANG "${_hazel_lang}"
                    FLAG "${FLAG}"
                    OUT_VAR ${_hazel_check_var}
                )
            endif()

            if(${${_hazel_check_var}})
                set(_hazel_supported_for_any_lang ON)
                break()
            endif()
        endforeach()

        if(_hazel_supported_for_any_lang)
            target_link_options(${ARG_TARGET} ${ARG_SCOPE} "SHELL:${FLAG}")
        else()
            message(
                FATAL_ERROR
                "target_apply_linker_settings: Linker flag '${FLAG}' is unsupported for languages '${ARG_LANG}'."
            )
        endif()
    endforeach()

    if(ARG_SCRIPT)
        get_filename_component(SCRIPT_ABS_PATH "${ARG_SCRIPT}" ABSOLUTE)
        if(EXISTS "${SCRIPT_ABS_PATH}")
            message(STATUS "Applying Linker Script: ${SCRIPT_ABS_PATH}")
            target_link_options(${ARG_TARGET} ${ARG_SCOPE} "-T${SCRIPT_ABS_PATH}")
            set_target_properties(${ARG_TARGET} PROPERTIES LINK_DEPENDS "${SCRIPT_ABS_PATH}")
        else()
            message(FATAL_ERROR "Linker script not found at: ${SCRIPT_ABS_PATH}")
        endif()
    endif()
endfunction()

function(target_apply_compile_settings)
    set(options "")
    set(oneValueArgs TARGET SCOPE)
    set(multiValueArgs FLAGS LANG)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "target_apply_compile_settings: TARGET argument is required.")
    endif()
    if(NOT TARGET ${ARG_TARGET})
        message(FATAL_ERROR "target_apply_compile_settings: Target '${ARG_TARGET}' does not exist.")
    endif()

    if(NOT ARG_LANG)
        set(ARG_LANG "C")
    endif()

    if(NOT ARG_SCOPE)
        set(ARG_SCOPE "PRIVATE")
    endif()

    # Iterate over every language requested (e.g. C, then CXX)
    foreach(LANG_ITr IN LISTS ARG_LANG)
        if(
            NOT LANG_ITr STREQUAL "C"
            AND NOT LANG_ITr STREQUAL "CXX"
            AND NOT LANG_ITr STREQUAL "ASM"
        )
            message(WARNING "Unsupported LANG '${LANG_ITr}'")
            continue()
        endif()

        foreach(FLAG IN LISTS ARG_FLAGS)
            # Unique variable: COMPILER_SUPPORTS_CXX_-Wall, etc.
            string(REGEX REPLACE "[^a-zA-Z0-9_+=.-]" "_" SAFE_FLAG_NAME "${FLAG}")
            set(CHECK_VAR "COMPILER_SUPPORTS_${LANG_ITr}_${SAFE_FLAG_NAME}")

            if(LANG_ITr STREQUAL "C")
                check_c_compiler_flag("${FLAG}" ${CHECK_VAR})
            elseif(LANG_ITr STREQUAL "CXX")
                check_cxx_compiler_flag("${FLAG}" ${CHECK_VAR})
            else()
                if(COMMAND check_asm_compiler_flag)
                    check_asm_compiler_flag("${FLAG}" ${CHECK_VAR})
                else()
                    check_c_compiler_flag("${FLAG}" ${CHECK_VAR})
                endif()
            endif()

            # This ensures -std=c23 is NOT passed to C++ files, and -fno-rtti is NOT passed to C files.
            if(${${CHECK_VAR}})
                target_compile_options(
                    ${ARG_TARGET}
                    ${ARG_SCOPE}
                    "$<$<COMPILE_LANGUAGE:${LANG_ITr}>:${FLAG}>"
                )
            endif()
        endforeach()
    endforeach()
endfunction()
