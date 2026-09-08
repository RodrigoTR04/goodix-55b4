# SPDX-License-Identifier: LGPL-2.1-or-later

project(
  'libfprint-goodix-55b4',
  ['c', 'cpp'],
  version: '0.1.0',
  default_options: [
    'c_std=c11',
    'cpp_std=c++17',
    'warning_level=3',
    'werror=true',
  ],
)

inc = include_directories('src')
threads_dep = dependency('threads')
libusb_dep = dependency('libusb-1.0', version: '>= 1.0.20')
openssl_dep = dependency('openssl', version: '>= 1.1.1')
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')
if not cc.has_header_symbol('openssl/ssl.h', 'SSL_OP_CLEANSE_PLAINTEXT', dependencies: openssl_dep)
  error('Private frame handling requires OpenSSL with SSL_OP_CLEANSE_PLAINTEXT')
endif

opencv_dep = dependency('opencv5', required: false)
if not opencv_dep.found()
  opencv_dep = dependency('opencv4', required: false)
endif
if get_option('sigfm').enabled() and not opencv_dep.found()
  error('SIGFM was explicitly enabled, but neither opencv5 nor opencv4 was found')
endif
sigfm_enabled = opencv_dep.found() and not get_option('sigfm').disabled()
if sigfm_enabled
  cpp_runtime_dep = cpp.find_library('stdc++', required: false)
  if not cpp_runtime_dep.found()
    error('SIGFM requires the C++ runtime library')
  endif
endif

goodix_lib = static_library(
  'goodix',
  [
    'src/goodix_activation.c',
    'src/goodix_calibration.c',
    'src/goodix_command.c',
    'src/goodix_config.c',
    'src/goodix_finger.c',
    'src/goodix_frame.c',
    'src/goodix_image.c',
    'src/goodix_key.c',
    'src/goodix_protocol.c',
    'src/goodix_psk.c',
    'src/goodix_seal.c',
    'src/goodix_session.c',
    'src/goodix_tls.c',
    'src/goodix_transport.c',
  ],
  include_directories: inc,
  dependencies: openssl_dep,
)
goodix_dep = declare_dependency(
  include_directories: inc,
  link_with: goodix_lib,
  dependencies: openssl_dep,
)

if sigfm_enabled
  sigfm_lib = static_library(
    'goodix-sigfm',
    'src/goodix_sigfm.cpp',
    include_directories: inc,
    dependencies: [opencv_dep, cpp_runtime_dep],
  )
endif

executable(
  'goodix-probe',
  'tools/goodix_probe.c',
  dependencies: [goodix_dep, libusb_dep, threads_dep],
  install: false,
)

executable(
  'goodix-cycle',
  'tools/goodix_cycle.c',
  dependencies: [goodix_dep, libusb_dep],
  install: false,
)

# Synthetic data only: no sensor, pairing keys, or enrolled fingerprints.
foreach name : ['tls', 'key', 'psk', 'activation', 'seal']
  test(name, executable('test-' + name, 'tests/test_' + name + '.c',
       c_args: ['-UNDEBUG'], dependencies: goodix_dep))
endforeach
if sigfm_enabled
  test('sigfm', executable('test-sigfm', 'tests/test_sigfm.cpp',
       cpp_args: ['-UNDEBUG'], include_directories: inc, link_with: sigfm_lib,
       dependencies: [opencv_dep, cpp_runtime_dep]))
endif
