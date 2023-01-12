// Copyright (c) 2021 Christopher Antos
// License: http://opensource.org/licenses/MIT

recognition recognize_command(const char* line, const char* word, bool quoted, bool& ready, str_base* file);

HANDLE get_recognizer_event();
bool check_recognizer_refresh();

extern "C" void end_recognizer();
void shutdown_recognizer();
