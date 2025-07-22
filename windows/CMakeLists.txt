cmake_minimum_required(VERSION 3.10)

# Project-level configuration.
set(PROJECT_NAME "dnssec_proof")
project(${PROJECT_NAME} LANGUAGES CXX)

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Replace add_subdirectory that references old C++ code with Cargokit:
include("../cargokit/cmake/cargokit.cmake")
apply_cargokit(${PROJECT_NAME} ../rust dnssec_proof "")
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(dnssec_proof_bundled_libraries
  # Defined in ../src/CMakeLists.txt.
  # This can be changed to accommodate different builds.

  # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  # Replace original target file with the one produced by Cargokit:
  "${${PROJECT_NAME}_cargokit_lib}"
  # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  PARENT_SCOPE
)