cmake_minimum_required(VERSION 3.24)

project(case_folding_fs LANGUAGES CXX)

find_package(ICU REQUIRED COMPONENTS uc)
find_package(Boost REQUIRED COMPONENTS headers)

include(FindPkgConfig)
pkg_check_modules(fuse3 IMPORTED_TARGET fuse3)

add_executable(case-folding-fs
	main.cpp
)

target_link_libraries(case-folding-fs ICU::uc Boost::headers PkgConfig::fuse3)
target_compile_features(case-folding-fs PRIVATE cxx_std_20)

add_custom_target(test-fs
	COMMAND $<TARGET_FILE:case-folding-fs> -o debug "${CMAKE_CURRENT_SOURCE_DIR}/test-dir"
	VERBATIM
	USES_TERMINAL
)
