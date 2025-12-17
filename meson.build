project('io-renef', 'c', license : 'MIT', meson_version : '>=1.00', version : '0.1.0')

r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: true).stdout().strip()

sources = [
	'src/io_renef.c',
	'src/renef_socket.c',
	'src/renef_commands.c',
	'src/renef_memory.c',
]

lib = library('iorenef', sources,
	dependencies : [
		dependency('r_io')
	],
	include_directories: include_directories('src'),
	install_dir: r2_plugdir,
	install: true
)
