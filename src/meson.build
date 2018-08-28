#
# target: libndhcp4.so
#

libndhcp4_symfile = join_paths(meson.current_source_dir(), 'libndhcp4.sym')

libndhcp4_deps = [
        dep_crbtree,
]

libndhcp4_private = static_library(
        'ndhcp4-private',
        [
                'n-dhcp4-client.c',
                'n-dhcp4-message.c',
                'n-dhcp4-network.c',
                'util/packet.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common'
        ],
        dependencies: libndhcp4_deps,
        pic: true,
)

libndhcp4_shared = shared_library(
        'ndhcp4',
        objects: libndhcp4_private.extract_all_objects(),
        dependencies: libndhcp4_deps,
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libndhcp4_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libndhcp4_symfile)
        ],
)

libndhcp4_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libndhcp4_private,
        dependencies: libndhcp4_deps,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('n-dhcp4.h')

        mod_pkgconfig.generate(
                libraries: libndhcp4_shared,
                version: meson.project_version(),
                name: 'libndhcp4',
                filebase: 'libndhcp4',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libndhcp4_shared)
test('API Symbol Visibility', test_api)

test_packet = executable('test-packet', ['util/test-packet.c'], dependencies: libndhcp4_dep)
test('Packet Utility Library', test_packet)

test_message = executable('test-message', ['test-message.c'], dependencies: libndhcp4_dep)
test('Message Handling', test_message)

#test_ = executable('test-', ['test-.c'], dependencies: libndhcp4_dep)
#test('', test_)
