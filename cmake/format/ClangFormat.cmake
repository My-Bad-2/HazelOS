include_guard()

function(add_clang_format_target)
    set(oneValueArgs TARGET_NAME)
    set(multiValueArgs DIRECTORIES)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET_NAME)
        message(FATAL_ERROR "add_clang_format_target: TARGET_NAME argument is required.")
    endif()

    if(NOT ARG_DIRECTORIES)
        message(FATAL_ERROR "add_clang_format_target: DIRECTORIES argument is required.")
    endif()

    find_program(CLANG_FORMAT_EXE clang-format)

    if(NOT CLANG_FORMAT_EXE)
        message(
            WARNING
            "clang-format not found! The '${ARG_TARGET_NAME}' target will be unavailable."
        )
        return()
    endif()

    set(FILE_EXTENSIONS
        "*.cpp"
        "*.cxx"
        "*.cc"
        "*.c"
        "*.hpp"
        "*.hxx"
        "*.hh"
        "*.h"
    )

    # Loop through directories and gather files
    set(ALL_SOURCE_FILES "")
    foreach(DIR ${ARG_DIRECTORIES})
        if(NOT IS_DIRECTORY "${DIR}")
            message(STATUS "Skipping clang-format scan for missing directory: ${DIR}")
            continue()
        endif()

        foreach(EXT ${FILE_EXTENSIONS})
            file(GLOB_RECURSE FOUND_FILES CONFIGURE_DEPENDS "${DIR}/${EXT}")
            list(APPEND ALL_SOURCE_FILES ${FOUND_FILES})
        endforeach()
    endforeach()

    list(REMOVE_DUPLICATES ALL_SOURCE_FILES)

    if(NOT ALL_SOURCE_FILES)
        message(STATUS "No sources found for clang-format in given directories.")
        return()
    endif()

    add_custom_target(
        ${ARG_TARGET_NAME}
        COMMAND
            ${CLANG_FORMAT_EXE} -i # In-place edit
            -style=file # Looks for .clang-format file
            ${ALL_SOURCE_FILES}
        COMMENT "Running clang-format on ${ARG_TARGET_NAME} sources..."
        VERBATIM
    )

    add_custom_target(
        ${ARG_TARGET_NAME}_check
        COMMAND
            ${CLANG_FORMAT_EXE} --dry-run # Don't edit, just check
            --Werror # Return error code if formatting is needed
            -style=file ${ALL_SOURCE_FILES}
        COMMENT "Checking code formatting compliance..."
        VERBATIM
    )
endfunction()
