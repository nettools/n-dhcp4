#
# target: libndhcp4.so
# We build both, a static and a shared library. We want our tests to get access
# to internals, so we link them statically.
#

libndhcp4_private = static_library('ndhcp4-private',
                                 [
                                        'client.c',
                                        'message.c',
                                        'network.c',
                                 ],
                                 c_args: [
                                        '-fvisibility=hidden',
                                        '-fno-common'
                                 ],
                                 pic: true)
install_headers('n-dhcp4.h')
libndhcp4_symfile = join_paths(meson.current_source_dir(), 'libndhcp4.sym')
libndhcp4_shared = shared_library('ndhcp4',
                                  objects: libndhcp4_private.extract_all_objects(),
                                  install: true,
                                  soversion: 0,
                                  link_depends: libndhcp4_symfile,
                                  link_args: [
                                          '-Wl,--no-undefined',
                                          '-Wl,--version-script=@0@'.format(libndhcp4_symfile)
                                  ])
mod_pkgconfig.generate(libraries: libndhcp4_shared,
                       version: meson.project_version(),
                       name: 'libndhcp4',
                       filebase: 'libndhcp4',
                       description: 'DHCPv4 library')

#
# target: test-api
# The test-api program explicitly links against the shared library, since it
# tests for symbol visibility.
#

test_api = executable('test-api',
                      ['test-api.c'],
                      link_with: libndhcp4_shared)
test('API Symbol Visibility', test_api)

#
# target: test-*
# All other tests are listed here. They link against the static library, so
# they can access internals for verification.
#

test_message = executable('test-message',
                          ['test-message.c'],
                          link_with: libndhcp4_private)
test('Message handling', test_message)
