include_guard()

include("${CMAKE_CURRENT_LIST_DIR}/../misc/FlagProbes.cmake")

function(project_configure_linker)
    if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
        set(_hazel_default_linker "lld")
    else()
        set(_hazel_default_linker "ld")
    endif()

    set(${PROJECT_NAME}_LINKER_OPTION "${_hazel_default_linker}" CACHE STRING "Linker to be used")

    set(_hazel_linker_values "lld" "ld")
    set_property(CACHE ${PROJECT_NAME}_LINKER_OPTION PROPERTY STRINGS ${_hazel_linker_values})

    set(_hazel_linker_option "${${PROJECT_NAME}_LINKER_OPTION}")

    list(FIND _hazel_linker_values "${_hazel_linker_option}" _hazel_linker_index)
    if(_hazel_linker_index EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported linker option '${_hazel_linker_option}'. Supported values: ${_hazel_linker_values}"
        )
    endif()

    set(_hazel_fuse_ld_flag "-fuse-ld=${_hazel_linker_option}")
    hazel_check_link_driver_flag(
        LANG "C"
        FLAG "${_hazel_fuse_ld_flag}"
        OUT_VAR _hazel_supports_fuse_ld_c
    )
    hazel_check_link_driver_flag(
        LANG "CXX"
        FLAG "${_hazel_fuse_ld_flag}"
        OUT_VAR _hazel_supports_fuse_ld_cxx
    )

    if(NOT _hazel_supports_fuse_ld_c OR NOT _hazel_supports_fuse_ld_cxx)
        message(
            FATAL_ERROR
            "Compiler family '${CMAKE_C_COMPILER_ID}/${CMAKE_CXX_COMPILER_ID}' does not support '${_hazel_fuse_ld_flag}'."
        )
    endif()

    set(_hazel_link_flags "${${PROJECT_NAME}_LINK_FLAGS}")
    list(APPEND _hazel_link_flags "${_hazel_fuse_ld_flag}")
    list(REMOVE_DUPLICATES _hazel_link_flags)
    set(${PROJECT_NAME}_LINK_FLAGS "${_hazel_link_flags}" PARENT_SCOPE)
endfunction()
