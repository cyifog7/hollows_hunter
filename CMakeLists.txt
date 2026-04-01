cmake_minimum_required (VERSION 3.12)
project (hollows_hunter)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(HH_BUILD_TESTING "Enable testing for HollowsHunter" ON)
option (PECONV_LIB_INSTALL OFF)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
option( USE_ETW "Use ETW" ON )

if(USE_ETW)
    add_compile_definitions(USE_ETW)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

	enable_language(RC)

	set(CMAKE_RC_COMPILE_OBJECT
		"<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")

	add_compile_definitions(
		_WIN32_WINNT=1536
	)
	if (LINK_STATICALLY)
		add_link_options(
			-static
			-static-libgcc
			-static-libstdc++
		)
	endif()

endif()

set ( M_PESIEVE "pe-sieve" )
set ( M_PARAMKIT "paramkit" )

set (PESIEVE_DIR "${PROJECT_SOURCE_DIR}/deps/${M_PESIEVE}" CACHE PATH "PE-sieve main path")
include_directories ( ${PESIEVE_DIR}/include )

set (PARAMKIT_DIR "${CMAKE_SOURCE_DIR}/deps/${M_PARAMKIT}/${M_PARAMKIT}" CACHE PATH "ParamKit main path" )
include_directories ( ${PARAMKIT_DIR}/include )

set (srcs
	src/main.cpp
	src/term_util.cpp
	src/hh_scanner.cpp
	src/hh_params.cpp
	src/hh_report.cpp
	src/hh_config.cpp
	src/params_info/pe_sieve_params_info.cpp
	src/util/suspend.cpp
	src/util/process_privilege.cpp
	src/util/time_util.cpp
	src/util/strings_util.cpp
	src/util/vt_lookup.cpp
)

set (hdrs
	src/term_util.h
	src/hh_scanner.h
	src/hh_params.h
	src/hh_report.h
	src/hh_global.h
	src/hh_config.h
	src/params_info/params.h
	src/params_info/pe_sieve_params_info.h
	src/util/suspend.h
	src/util/ntddk.h
	src/util/process_privilege.h
	src/util/time_util.h
	src/util/strings_util.h
	src/util/process_util.h
	src/util/vt_lookup.h
)

if(USE_ETW)
	set (srcs
		${srcs}
		src/etw_listener.cpp
		src/etw_settings.cpp
	)

	set (hdrs
		${hdrs}
		src/etw_listener.h
		src/etw_settings.h
		deps/krabsetw/krabs/krabs.hpp
	)
endif()

set (rsrc
	src/resources.h
	src/hh_res.rc
	src/hh_ver_short.h
	src/hollows_hunter.manifest
)

if (NOT PESIEVE_AS_DLL)
	set ( PESIEVE_AS_STATIC_LIB ON CACHE BOOL "Enable building PE-sieve as a static library" FORCE)
endif()

if (NOT PESIEVE_AS_STATIC_LIB)
	set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
endif()

add_subdirectory ( ${PESIEVE_DIR} )
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE PATH "PE-sieve library path" )

add_subdirectory ( ${PARAMKIT_DIR} )
set ( PARAMKIT_LIB $<TARGET_FILE:paramkit> CACHE PATH "ParamKit library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} src/main.cpp )
target_include_directories( ${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR} )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} "psapi.lib" "ntdll.lib" "winhttp.lib" "crypt32.lib")

add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )
target_compile_definitions(${PROJECT_NAME} PUBLIC -DUNICODE)
target_compile_definitions(${M_PARAMKIT} PUBLIC -DUNICODE)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	target_link_options( ${PROJECT_NAME} PRIVATE "/MANIFEST:NO")
endif()

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

if(HH_BUILD_TESTING)
	enable_testing()

	add_test (TestRuns ${CMAKE_INSTALL_PREFIX}/hollows_hunter -?)
	set_tests_properties(TestRuns PROPERTIES PASS_REGULAR_EXPRESSION "HollowsHunter")

	add_test (TestFalsePositives ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out)
	set_tests_properties(TestFalsePositives PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : 0")

	add_test (TestCaching ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache E)
	set_tests_properties(TestCaching PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : 0")

	add_test (TestIatScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache E -iat 1)
	set_tests_properties(TestIatScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	add_test (TestHooksScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache E -hooks)
	set_tests_properties(TestHooksScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	add_test (TestThreadsScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache E -threads)
	set_tests_properties(TestThreadsScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	add_test (TestCodeScanNoDump ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache E -shellc P -ofilter 2)
	set_tests_properties(TestCodeScanNoDump PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")
endif()
