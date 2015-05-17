find_path(KJ_INCLUDE_DIR kj/main.h PATHS)
find_library(KJ_LIBRARY NAMES kj PATHS)
find_library(KJ_LIBRARY_DEBUG NAMES kj PATHS)
find_library(KJ_ASYNC_LIBRARY NAMES kj-async PATHS)
find_library(KJ_ASYNC_LIBRARY_DEBUG NAMES kj-async PATHS)
find_library(KJ_TEST_LIBRARY NAMES kj-test PATHS)
find_library(KJ_TEST_LIBRARY_DEBUG NAMES kj-test PATHS)
set(KJ_BASE_LIBRARIES
        optimized ${KJ_LIBRARY}
        debug     ${KJ_LIBRARY_DEBUG}
        )
set(KJ_ASYNC_LIBRARIES
        optimized ${KJ_ASYNC_LIBRARY}
        debug     ${KJ_ASYNC_LIBRARY}
        )
set(KJ_TEST_LIBRARIES
        optimized ${KJ_TEST_LIBRARY}
        debug     ${KJ_TEST_LIBRARY}
        )
set(KJ_LIBRARIES ${KJ_BASE_LIBRARIES} ${KJ_ASYNC_LIBRARIES} ${KJ_TEST_LIRARY})
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(KJ REQUIRED_VARS KJ_LIBRARIES KJ_INCLUDE_DIR)
mark_as_advanced(KJ_INCLUDE_DIR)
