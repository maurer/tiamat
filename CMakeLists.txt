cmake_minimum_required(VERSION 2.8)
project(bap-container)
set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    "${CMAKE_SOURCE_DIR}/cmake/Modules/"
   )
find_package(Capnproto REQUIRED)
find_package(LLVM REQUIRED CONFIG)
include_directories(${CAPNPROTO_INCLUDE_DIRS})
CAPNPROTO_GENERATE_CPP(CAPN_SRCS CAPN_HDRS holmes.capnp)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
add_executable(obj.holmes dumpobj.cpp ${CAPN_SRCS} ${CAPN_HDRS})
target_link_libraries(obj.holmes ${CAPNPROTO_LIBRARIES})
llvm_map_components_to_libraries(LLVM_LIBS support core object)
target_link_libraries(obj.holmes ${LLVM_LIBS})
CAPNPROTO_ADD_CXXFLAGS()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} -Wall -Werror")
