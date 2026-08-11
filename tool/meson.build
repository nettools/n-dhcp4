executable(
    'check-dhcp4',
    'check-dhcp4.c',
    include_directories: src_inc,
    dependencies: gio_unix_dep,
    link_with: libndhcp4_shared,
    install: true,
    install_dir: get_option('bindir')
)
