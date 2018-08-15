project(
        'n-dhcp4',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'c_std=c11',
        ],
)
project_description = 'Dynamic Host Configuration Protocol for IPv4'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

sub_crbtree = subproject('c-rbtree')

dep_crbtree = sub_crbtree.get_variable('libcrbtree_dep')

subdir('src')
