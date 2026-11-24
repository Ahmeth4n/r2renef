project('io-renef', 'c', license : 'MIT', meson_version : '>=1.00', version : '0.2.0')

r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: true).stdout().strip()
threads = dependency('threads')

# no radare2 in these two: the unit tests build them on their own
proto_sources = [
	'src/renef_proto.c',
	'src/renef_socket.c',
]

sources = [
	'src/io_renef.c',
	'src/renef_session.c',
	'src/renef_memory.c',
	'src/renef_maps.c',
	'src/renef_commands.c',
] + proto_sources

lib = library('iorenef', sources,
	dependencies : [
		dependency('r_io'),
		threads,
	],
	include_directories: include_directories('src'),
	install_dir: r2_plugdir,
	install: true
)

test('proto', executable('test_proto', ['tests/test_proto.c', 'src/renef_proto.c']))
test('socket', executable('test_socket', ['tests/test_socket.c'] + proto_sources, dependencies : threads),
	timeout : 60)

# real r2 + the plugin just built (loaded with -I, not installed) + a mock
# renef_server; skips itself (exit 77) without a `lua` interpreter
python = find_program('python3', required : false)
if python.found()
	test('integration', python,
		args : [meson.current_source_dir() / 'tests' / 'integration_test.py', '--plugin', lib.full_path()],
		depends : lib,
		timeout : 900)
endif
