set(GTEST_SOURCE_DIR "${PROJECT_SOURCE_DIR}/thirdparty/googletest")
add_subdirectory(${GTEST_SOURCE_DIR})
include_directories(${GTEST_SOURCE_DIR}/googletest/include)
