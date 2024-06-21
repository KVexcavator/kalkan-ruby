require 'mkmf'
dir_config('jansson')
have_library('jansson', 'json_dumps') or abort "jansson library is missing."
create_makefile('kalkancrypt/kalkancrypt')
