include_guard()

include(CMakeParseArguments)

function(project_enable_doxygen)
    set(options ALL)
    set(oneValueArgs TARGET_NAME OUTPUT_DIR MAIN_PAGE MARKDOWN_OUTPUT)
    set(multiValueArgs INPUT_DIRS EXCLUDE_PATTERNS)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "project_enable_doxygen: unsupported arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()

    if(NOT ARG_TARGET_NAME)
        set(_hazel_docs_target_name "doxygen-docs")
    else()
        set(_hazel_docs_target_name "${ARG_TARGET_NAME}")
    endif()

    if(NOT ARG_OUTPUT_DIR)
        set(_hazel_docs_output_dir "${CMAKE_CURRENT_BINARY_DIR}/docs")
    else()
        set(_hazel_docs_output_dir "${ARG_OUTPUT_DIR}")
    endif()

    if(NOT ARG_INPUT_DIRS)
        set(_hazel_docs_input_dirs "${PROJECT_SOURCE_DIR}")
    else()
        set(_hazel_docs_input_dirs "${ARG_INPUT_DIRS}")
    endif()

    if(NOT ARG_MAIN_PAGE AND EXISTS "${CMAKE_SOURCE_DIR}/README.md")
        set(_hazel_docs_main_page "${CMAKE_SOURCE_DIR}/README.md")
    else()
        set(_hazel_docs_main_page "${ARG_MAIN_PAGE}")
    endif()

    if(NOT ARG_EXCLUDE_PATTERNS)
        set(_hazel_docs_exclude_patterns "*/_deps/*" "*/cache/*" "*/build/*" "*/boot/*.h")
    else()
        set(_hazel_docs_exclude_patterns "${ARG_EXCLUDE_PATTERNS}")
    endif()

    find_package(Doxygen QUIET)
    if(NOT DOXYGEN_FOUND)
        message(STATUS "Doxygen not found; documentation targets will not be generated.")
        return()
    endif()

    set(_hazel_docs_xml_dir "${_hazel_docs_output_dir}/xml")
    set(_hazel_docs_markdown_dir "${_hazel_docs_output_dir}/markdown")
    set(_hazel_docs_xml_target "${_hazel_docs_target_name}-xml")

    if(NOT ARG_MARKDOWN_OUTPUT)
        set(_hazel_docs_markdown_output "${_hazel_docs_markdown_dir}/api.md")
    else()
        set(_hazel_docs_markdown_output "${ARG_MARKDOWN_OUTPUT}")
    endif()

    find_program(_hazel_moxygen_exe NAMES moxygen)
    if(NOT _hazel_moxygen_exe)
        message(STATUS "moxygen not found; markdown documentation target will not be generated.")
        return()
    endif()

    set(DOXYGEN_QUIET YES)
    set(DOXYGEN_MARKDOWN_SUPPORT YES)
    set(DOXYGEN_AUTOLINK_SUPPORT YES)
    set(DOXYGEN_EXTRACT_ALL NO)
    set(DOXYGEN_GENERATE_HTML NO)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_GENERATE_MAN NO)
    set(DOXYGEN_GENERATE_RTF NO)
    set(DOXYGEN_GENERATE_XML YES)
    set(DOXYGEN_OUTPUT_DIRECTORY "${_hazel_docs_output_dir}")
    set(DOXYGEN_XML_OUTPUT "xml")
    set(DOXYGEN_EXCLUDE_PATTERNS ${_hazel_docs_exclude_patterns})

    if(NOT _hazel_docs_main_page STREQUAL "")
        set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${_hazel_docs_main_page}")
    endif()

    if(ARG_ALL)
        doxygen_add_docs(
            ${_hazel_docs_xml_target}
            ${_hazel_docs_input_dirs}
            ALL
            COMMENT "Generating Doxygen XML documentation"
        )
    else()
        doxygen_add_docs(
            ${_hazel_docs_xml_target}
            ${_hazel_docs_input_dirs}
            COMMENT "Generating Doxygen XML documentation"
        )
    endif()

    add_custom_target(
        ${_hazel_docs_target_name}
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_hazel_docs_markdown_dir}"
        COMMAND
            "${_hazel_moxygen_exe}" --anchors --output "${_hazel_docs_markdown_output}"
            "${_hazel_docs_xml_dir}"
        DEPENDS ${_hazel_docs_xml_target}
        COMMENT "Generating Markdown documentation from Doxygen XML with moxygen"
        VERBATIM
    )

    message(
        STATUS
        "Registered docs targets '${_hazel_docs_xml_target}' and '${_hazel_docs_target_name}'. Markdown output: ${_hazel_docs_markdown_output}"
    )
endfunction()
