if(UNIX)
  add_definitions(-D_UNIX)
elseif(WIN32)
  add_definitions(-D_WIN32)
elseif(APPLE)
  add_definitions(-D_APPLE)
endif()


include_directories(
  ${PROJECT_SOURCE_DIR}/src)

set(SOURCE_FILES
  main.cc
  core/event_loop.h
  core/event_loop.cc
  core/event_listener.h
  core/event_listener.cc
  network/server.h
  network/server.cc
  network/http_server.h
  network/http_server.cc
  utils/misc_util.h
  utils/error_util.h
  utils/error_util.cc
  utils/file_util.h
  utils/file_util.cc
  # utils/env.h
  # utils/env.cc
  # utils/env_poxiv.cc
  # utils/status.h
  # utils/status.cc
  utils/string_util.h
  utils/string_util.cc
  utils/log.h
  utils/log.cc
  common/singleton.h)

add_executable(MyServer "")

target_sources(MyServer
  PRIVATE
  ${SOURCE_FILES})

add_library(libMyServer "")
target_sources(libMyServer
  PRIVATE
  ${SOURCE_FILES})
