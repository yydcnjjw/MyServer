include_directories(
  ${PROJECT_SOURCE_DIR}/src)

add_executable(runUnitTests
  gtest.cc)

target_link_libraries(runUnitTests
  gtest gtest_main libMyServer)
 
