#pragma once

#include <core/str.h>

enum class match_type : unsigned char;

struct match_display_filter_entry
{
    short visible_display;      // Visible characters, not counting ANSI escape codes.
    short visible_description;  // Visible characters, not counting ANSI escape codes.
    const char* match;          // Match string (pointer into buffer).
    const char* display;        // Display string (pointer into buffer).
    const char* description;    // Description string (pointer into buffer).
    unsigned char type;         // Match type.
    char append_char;           // Append character.
    unsigned char flags;        // Match flags.
    char buffer[1];             // Variable length buffer containing the PACKED MATCH FORMAT.
};
typedef struct match_display_filter_entry match_display_filter_entry;

// Match display filter entry [0] is a placeholder and is ignored except in two
// ways:
//  1.  If the entry is nullptr, the list is empty.
//  2.  If its visible_len is negative, then force the list to be displayed in a
//      single column.
typedef match_display_filter_entry** rl_match_display_filter_func_t(char**);
extern rl_match_display_filter_func_t *rl_match_display_filter_func;

extern const char *_rl_description_color;
extern const char *_rl_filtered_color;
extern const char *_rl_arginfo_color;
extern const char *_rl_selected_color;

void reset_tmpbuf(void);
void mark_tmpbuf(void);
const char* get_tmpbuf_rollback(void);
void rollback_tmpbuf(void);
void append_tmpbuf_char(char c);
void append_tmpbuf_string(const char* s, int len);
void flush_tmpbuf(void);
void append_display(const char* to_print, int selected, const char* color);
int append_filename(char* to_print, const char* full_pathname, int prefix_bytes, int can_condense, match_type type, int selected, int* vis_stat_char);
void pad_filename(int len, int pad_to_width, int selected);
bool get_match_color(const char *f, match_type type, str_base& out);

void free_filtered_matches(match_display_filter_entry** filtered_matches);
int printable_len(const char* match, match_type type);

#define DESC_ONE_COLUMN_THRESHOLD       9

// Flags in the PACKED MATCH FORMAT:
#define MATCH_FLAG_APPEND_DISPLAY       0x01
#define MATCH_FLAG_HAS_SUPPRESS_APPEND  0x02
#define MATCH_FLAG_SUPPRESS_APPEND      0x04

// For display_matches, the matches array must contain specially formatted
// match entries:
//
//  TYPE (unsigned char), when rl_completion_matches_include_type
//  MATCH (nul terminated char string)
//  FLAGS (unsigned char)
//  DISPLAY (nul terminated char string)
//  DESCRIPTION (nul terminated char string)
extern "C" void display_matches(char **matches);

extern void override_line_state(const char* line, const char* needle, int point);
#ifdef DEBUG
extern bool is_line_state_overridden();
#endif

class override_match_line_state
{
public:
    override_match_line_state() { assert(!is_line_state_overridden()); }
    ~override_match_line_state() { override_line_state(nullptr, nullptr, 0); }
    void override(int start, int end, const char* needle, char quote_char=0);
private:
    str_moveable m_line;
};

char need_leading_quote(const char* match, bool force_filename_completion_desired=false);
