include_guard()

function(add_clang_tidy_target)
    set(oneValueArgs TARGET_NAME)
    set(multiValueArgs DIRECTORIES)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET_NAME)
        message(FATAL_ERROR "add_clang_tidy_target: TARGET_NAME argument is required.")
    endif()

    if(NOT ARG_DIRECTORIES)
        message(FATAL_ERROR "add_clang_tidy_target: DIRECTORIES argument is required.")
    endif()

    find_program(CLANG_TIDY_EXE clang-tidy)
    if(NOT CLANG_TIDY_EXE)
        message(WARNING "clang-tidy not found! Target '${ARG_TARGET_NAME}' disabled.")
        return()
    endif()

    # Find Source files
    set(FILE_EXTENSIONS "*.cpp" "*.cxx" "*.cc" "*.c")
    set(ALL_SOURCE_FILES "")

    foreach(DIR ${ARG_DIRECTORIES})
        if(NOT IS_DIRECTORY "${DIR}")
            message(STATUS "Skipping clang-tidy scan for missing directory: ${DIR}")
            continue()
        endif()

        foreach(EXT ${FILE_EXTENSIONS})
            file(GLOB_RECURSE FOUND_FILES CONFIGURE_DEPENDS "${DIR}/${EXT}")
            list(APPEND ALL_SOURCE_FILES ${FOUND_FILES})
        endforeach()
    endforeach()

    list(REMOVE_DUPLICATES ALL_SOURCE_FILES)

    if(NOT ALL_SOURCE_FILES)
        return()
    endif()

    # Create "Check" Target (Reports warnings, doesn't change files)
    add_custom_target(
        ${ARG_TARGET_NAME}
        COMMAND
            ${CLANG_TIDY_EXE} -p
            ${CMAKE_BINARY_DIR} # Point to build folder containing compile_commands.json
            ${ALL_SOURCE_FILES}
        COMMENT "Running clang-tidy analysis..."
        VERBATIM
    )

    # Create "Fix" Target (Automatically attempts to fix code)
    add_custom_target(
        ${ARG_TARGET_NAME}_fix
        COMMAND
            ${CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR} -fix -format-style=file # Reformat file
            ${ALL_SOURCE_FILES}
        COMMENT "Running clang-tidy with auto-fix..."
        VERBATIM
    )
endfunction()
