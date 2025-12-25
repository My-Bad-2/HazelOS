include_guard()

macro(project_configure_linker)
    include(CheckCXXCompilerFlag)

    set(
        ${PROJECT_NAME}_LINKER_OPTION
        "lld"
        CACHE STRING "Linker to be used"
    )

    set(${PROJECT_NAME}_LINKER_OPTION_VALUES "lld" "ld")
    set_property(
        CACHE
        ${PROJECT_NAME}_LINKER_OPTION
        PROPERTY STRINGS
        ${${PROJECT_NAME}_LINKER_OPTION_VALUES}
    )

    list(
        FIND
        ${PROJECT_NAME}_LINKER_OPTION_VALUES
        ${${PROJECT_NAME}_LINKER_OPTION}
        ${PROJECT_NAME}_LINKER_OPTION_INDEX
    )

    if(${${PROJECT_NAME}_LINKER_OPTION_INDEX} EQUAL -1)
        message(
            STATUS
            "Using custom linker: '${${PROJECT_NAME}_LINKER_OPTION}', explicitly supported entries are ${${PROJECT_NAME}_LINKER_OPTION_VALUES}")
    endif()

    list(
        APPEND
        ${PROJECT_NAME}_LINK_FLAGS
        "-fuse-ld=${${PROJECT_NAME}_LINKER_OPTION}"
    )
endmacro()