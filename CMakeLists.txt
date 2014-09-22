cmake_minimum_required(VERSION 2.8)
project(bap-container)
find_program(LLVM_CONFIG
   NAMES llvm-config llvm-config-3.5
   DOC "LLVM Config"
   PATHS
)
set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    "${CMAKE_SOURCE_DIR}/cmake/Modules/"
   )
find_package(Capnproto REQUIRED)

execute_process(COMMAND ${LLVM_CONFIG} --includedir
                OUTPUT_VARIABLE LLVM_INCLUDE_DIRS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --libs
                OUTPUT_VARIABLE LLVM_LIBS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --cxxflags
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --ldflags
                OUTPUT_VARIABLE LLVM_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --system-libs
                OUTPUT_VARIABLE LLVM_UNSTRIPPED_SYSTEMLIBS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
string(STRIP ${LLVM_UNSTRIPPED_SYSTEMLIBS} LLVM_SYSTEMLIBS)

include_directories(${CAPNPROTO_INCLUDE_DIRS})
CAPNPROTO_GENERATE_CPP(CAPN_SRCS CAPN_HDRS holmes.capnp)
include_directories(${CMAKE_CURRENT_BINARY_DIR} "/usr/include/llvm-3.5" ${LLVM_INCLUDE_DIRS})
add_executable(obj.holmes dumpobj.cpp ${CAPN_SRCS} ${CAPN_HDRS})
add_executable(chunk.holmes chunker.cpp ${CAPN_SRCS} ${CAPN_HDRS})
target_link_libraries(obj.holmes ${CAPNPROTO_LIBRARIES})
target_link_libraries(chunk.holmes ${CAPNPROTO_LIBRARIES})
target_link_libraries(obj.holmes ${LLVM_LIBS} ${LLVM_SYSTEMLIBS})
CAPNPROTO_ADD_CXXFLAGS()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} ${LLVM_LDFLAGS} -Wall -Werror")
set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} ${LLVM_LDFLAGS}")

install(TARGETS chunk.holmes obj.holmes
        RUNTIME DESTINATION bin)
