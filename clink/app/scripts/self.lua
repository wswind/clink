-- Copyright (c) 2012 Martin Ridgers
-- License: http://opensource.org/licenses/MIT

--------------------------------------------------------------------------------
-- NOTE: If you add any settings here update set.cpp to load (lua, app, self).

--------------------------------------------------------------------------------
local nothing = clink.argmatcher():nofiles()
local empty_arg = clink.argmatcher():addarg()
local empty_arg_nothing = clink.argmatcher():addarg():nofiles()
local file_loop = clink.argmatcher():addarg(clink.filematches):loop()

--------------------------------------------------------------------------------
local dir_matcher = clink.argmatcher():addarg(clink.dirmatches)

--------------------------------------------------------------------------------
local function make_inject_parser()
    local inject = clink.argmatcher()
    :addflags("-h", "-d"..empty_arg, "-p"..dir_matcher, "-q", "-l", "-s"..dir_matcher, "-?")
    :hideflags("-h", "-d", "-p", "-q", "-l", "-s", "-?")
    :addflags(
        "--help",
        "--pid"..empty_arg,
        "--profile"..dir_matcher,
        "--quiet",
        "--nolog",
        "--scripts"..dir_matcher)
    :adddescriptions({
        ["--help"]      = "Show help",
        ["--pid"]       = "Inject into the specified process ID",
        ["--profile"]   = { " dir", "Specifies an alternative path for profile data" },
        ["--quiet"]     = "Suppress copyright output",
        ["--nolog"]     = "Disable file logging",
        ["--scripts"]   = { " dir", "Alternative path to load .lua scripts from" },
    })
    return inject
end

--------------------------------------------------------------------------------
local autorun_dashdash = clink.argmatcher()
:addarg("--" .. make_inject_parser():addarg(clink.filematches):loop())

local autorun = clink.argmatcher()
:addflags("-h", "-a", "-?")
:hideflags("-h", "-a", "-?")
:addflags(
    "--allusers",
    "--help")
:addarg(
    "install"   .. autorun_dashdash,
    "uninstall" .. nothing,
    "show"      .. nothing,
    "set"       .. file_loop)
:adddescriptions({
    ["--allusers"]  = "Modifies autorun for all users (requires admin rights)",
    ["--help"]      = "Show help",
    ["install"]     = "Installs a command to cmd.exe's autorun to start Clink",
    ["uninstall"]   = "Does the opposite of 'install'",
    ["show"]        = "Displays the values of cmd.exe's autorun variables",
    ["set"]         = "Explicitly set cmd.exe's autorun string"})
:nofiles()

--------------------------------------------------------------------------------
local echo = clink.argmatcher()
:addflags("-h", "-v", "-?")
:hideflags("-h", "-v", "-?")
:addflags(
    "--help",
    "--verbose")
:adddescriptions({
    ["--help"] = "Show help",
    ["--verbose"] = "Print verbose diagnostic information about keypresses"})
:nofiles()

--------------------------------------------------------------------------------
local function is_prefix3(s, ...)
    for _,i in ipairs({ ... }) do
        if #i < 3 or #s < 3 then
            if i == s then
                return true
            end
        else
            if i:sub(1, #s) == s then
                return true
            end
        end
    end
    return false
end

--------------------------------------------------------------------------------
local function color_for_word_class(wc)
    local c
    if wc == "a" then
        c = settings.get("color.arg")
        if not c or #c == 0 then c = settings.get("color.input") end
    elseif wc == "c" then
        c = settings.get("color.cmd")
    elseif wc == "d" then
        c = settings.get("color.doskey")
    elseif wc == "f" then
        c = settings.get("color.flag")
    elseif wc == "o" then
        c = settings.get("color.input")
    elseif wc == "x" then
        c = settings.get("color.executable")
    elseif wc == "u" then
        c = settings.get("color.unrecognized")
    elseif wc == "n" then
        c = settings.get("color.unexpected")
    elseif wc == "m" then
        c = settings.get("color.argmatcher")
    end
    return c or ""
end

--------------------------------------------------------------------------------
local function classify_to_end(idx, line_state, classify, wc)
    local offset
    if true then
        -- Make info scoped so that the applycolor call cannot accidentally use
        -- info, and must use offset instead.
        local info = line_state:getwordinfo(idx)
        if info then
            offset = info.offset
        else
            info = line_state:getwordinfo(idx - 1)
            if info then
                offset = info.offset + info.length
            end
        end
    end
    if offset then
        local info = line_state:getwordinfo(line_state:getwordcount())
        local len = info.offset + info.length
        classify:applycolor(offset, len - offset + 1, color_for_word_class(wc))
    end
end

--------------------------------------------------------------------------------
local function color_handler(word_index, line_state, classify)
    local i = word_index
    local include_clear = true
    local include_bold = true
    local include_bright = true
    local include_underline = true
    local include_color = true
    local include_on = true
    local include_sgr = true
    local invalid = false

    while i <= line_state:getwordcount() do
        local word = line_state:getword(i)

        if word ~= "" then
            include_clear = false
            if word ~= "sgr" then
                include_sgr = false
            end
        end

        if word == "on" then
            if not include_on then
                invalid = true
                break
            end
            include_bold = false
            include_bright = true
            include_underline = false
            include_color = true
            include_on = false
        elseif is_prefix3(word, "bold", "nobold", "dim") then
            if not include_bold then
                invalid = true
                break
            end
            include_bold = false
        elseif is_prefix3(word, "bright") then
            if not include_bright then
                invalid = true
                break
            end
            include_bright = false
        elseif is_prefix3(word, "underline", "nounderline") then
            if not include_underline then
                invalid = true
                break
            end
            include_underline = false
        elseif is_prefix3(word, "default", "normal", "black", "red", "green",
                          "yellow", "blue", "cyan", "magenta", "white") then
            if not include_color then
                invalid = true
                break
            end
            include_bold = false
            include_bright = false
            include_underline = false
            include_color = false
        elseif word == "sgr" then
            if not include_sgr then
                invalid = true
                break
            end
            if classify then
                classify_to_end(i, line_state, classify, "a") --arg
                return {} -- classify has been handled
            end
            return {}
        elseif word ~= "" then
            invalid = true
            break
        end

        if classify then
            classify:classifyword(i, "a") --arg
        end

        i = i + 1
    end

    if classify and invalid then
        classify_to_end(i, line_state, classify, "n") --none
    end
    if classify or invalid then
        return {}
    end

    local list = {}
    if include_on then
        table.insert(list, "on")
    end
    if include_bold then
        table.insert(list, "bold")
        table.insert(list, "nobold")
    end
    if include_bright then
        table.insert(list, "bright")
    end
    if include_underline then
        table.insert(list, "underline")
        table.insert(list, "nounderline")
    end
    if include_color then
        table.insert(list, "default")
        table.insert(list, "normal")
        table.insert(list, "black")
        table.insert(list, "red")
        table.insert(list, "green")
        table.insert(list, "yellow")
        table.insert(list, "blue")
        table.insert(list, "cyan")
        table.insert(list, "magenta")
        table.insert(list, "white")
    end
    if include_sgr then
        table.insert(list, "sgr")
    end
    if include_clear then
        table.insert(list, "clear")
    end
    if #list == 0 then
        return nil
    end
    return list
end

--------------------------------------------------------------------------------
local function set_handler(match_word, word_index, line_state) -- luacheck: no unused
    return settings.list()
end

--------------------------------------------------------------------------------
local function value_handler(match_word, word_index, line_state, builder, classify) -- luacheck: no unused
    if word_index <= 3 then
        return
    end

    -- Use relative positioning to get the word, in case flags were used.
    local name = line_state:getword(word_index - 1)
    local info = settings.list(name)
    if not info then
        return
    end

    if info.type == "color" then
        return color_handler(word_index, line_state)
    elseif info.type == "string" then
        if name == "autosuggest.strategy" then
            return clink._list_suggesters()
        else
            return clink.filematches(line_state:getendword())
        end
    else
        return info.values
    end
end

--------------------------------------------------------------------------------
local function classify_handler(arg_index, word, word_index, line_state, classify)
    if arg_index == 1 then
        -- Classify the setting name.
        local info = settings.list(word, true)
        if info then
            classify:classifyword(word_index, "a") --arg
        else
            classify_to_end(word_index, line_state, classify, "n") --none
            return true
        end

        -- Classify the setting value.
        local idx = word_index + 1
        if idx > line_state:getwordcount() then
            return true
        end
        if info.type == "color" then
            color_handler(idx, line_state, classify)
            return true
        elseif info.type == "string" then
            -- If there are no matches listed, then it's a string field.  In
            -- that case classify the rest of the line as "other" words so they
            -- show up in a uniform color.
            classify_to_end(idx, line_state, classify, "o") --other
            return true
        elseif info.type == "int" then
            classify:classifyword(idx, "o") --other
        else
            local t = "n" --none
            local value = clink.lower(line_state:getword(idx))
            for _,i in ipairs(info.values) do
                if clink.lower(i) == value then
                    t = "a" --arg
                    break
                end
            end
            classify:classifyword(idx, t)
        end

        -- Anything further is unrecognized.
        classify_to_end(idx + 1, line_state, classify, "n") --none
    end
    return true
end

--------------------------------------------------------------------------------
local set = clink.argmatcher()
:addflags("-h", "-d", "-?")
:hideflags("-h", "-d", "-?")
:addflags("--help", "--describe")
:adddescriptions({["--help"] = "Show help"})
:adddescriptions({["--describe"] = "Show descriptions of settings (instead of values)"})
:addarg(set_handler)
:addarg(value_handler)
:setclassifier(classify_handler)

--------------------------------------------------------------------------------
local history = clink.argmatcher("history")
:addflags("-h", "-c"..nothing, "-d"..empty_arg_nothing, "-p"..file_loop, "-s"..file_loop)
:hideflags("-h", "-c", "-d", "-p", "-s")
:addflags(
    "--help",
    "--bare",
    "--show-time",
    "--time-format"..empty_arg,
    "--unique")
:adddescriptions({
    ["--help"]      = "Show help",
    ["--bare"]      = "Omit item numbers when printing history",
    ["--show-time"] = "Show history item timestamps, if any",
    ["--time-format"] = "Override the format string for showing timestamps",
    ["--unique"]    = "Remove duplicates when compacting history",
    ["add"]         = "Append the rest of the line to the history",
    ["clear"]       = "Completely clears the command history",
    ["compact"]     = "Compacts the history file",
    ["delete"]      = "Delete the Nth history item (negative indexes backwards)",
    ["expand"]      = "Print substitution result"})
:addarg(
    "add"       .. file_loop,
    "clear"     .. nothing,
    "compact"   .. nothing,
    "delete"    .. empty_arg_nothing,
    "expand"    .. file_loop)
:nofiles()

--------------------------------------------------------------------------------
local update = clink.argmatcher()
:addflags("-h", "-a", "-A", "-D", "-?")
:hideflags("-h", "-a", "-A", "-D", "-?")
:addflags("--help", "--allusers", "--allow-automatic", "--disallow-automatic")
:adddescriptions({
    ["--help"]      = "Show help",
    ["--allusers"]  = "Modify automatic updates for all users",
    ["--allow-automatic"] = "Clear regkey that disallows automatic updates",
    ["--disallow-automatic"] = "Set regkey that disallows automatic updates"})
:nofiles()

--------------------------------------------------------------------------------
local installscripts = clink.argmatcher()
:addflags("-h", "-l", "-?")
:hideflags("-h", "-l", "-?")
:addflags("--help", "--list")
:adddescriptions({
    ["--help"] = "Show help",
    ["--list"] = "List all installed script paths",
})
:addarg(clink.dirmatches)
:nofiles()

--------------------------------------------------------------------------------
local function uninstall_handler(match_word, word_index, line_state) -- luacheck: no unused
    local ret = {}
    for line in io.popen('"'..CLINK_EXE..'" uninstallscripts --list', "r"):lines() do
        table.insert(ret, line)
    end
    return ret
end

--------------------------------------------------------------------------------
local uninstallscripts = clink.argmatcher()
:addflags("-h", "-?", "-l", "-a")
:hideflags("-h", "-?", "-l", "-a")
:addflags("--help", "--list", "--all")
:adddescriptions({
    ["--help"] = "Show help",
    ["--list"] = "List all installed script paths",
    ["--all"] = "Uninstall all installed script paths",
})
:addarg(uninstall_handler)
:nofiles()

--------------------------------------------------------------------------------
local speed_parser = clink.argmatcher():addarg({fromhistory=true})
local width_parser = clink.argmatcher():addarg({fromhistory=true})
local emulation_parser = clink.argmatcher():addarg("native", "emulate", "auto")
local drawtest = clink.argmatcher()
:addflags(
    "-p", "--pause",
    "-s" .. speed_parser, "--speed" .. speed_parser,
    "-w" .. width_parser, "--width" .. width_parser,
    "-e" .. emulation_parser, "--emulation" .. emulation_parser,
    "-h", "--help", "-?")
:hideflags("-p", "-s", "-w", "-e", "-h", "-?")
:nofiles()

--------------------------------------------------------------------------------
local testbed = clink.argmatcher()
:addflags(
    "-d", "--hook",
    "-s" .. dir_matcher, "--scripts" .. dir_matcher,
    "-p" .. dir_matcher, "--profile" .. dir_matcher,
    "-h", "--help", "-?")
:hideflags("-d", "-s", "-p", "-h", "-?")
:nofiles()

--------------------------------------------------------------------------------
local function hide_tests()
    clink.onfiltermatches(function(matches)
        local keep = {}
        for _, m in ipairs(matches) do
            if m.match ~= "drawtest" and m.match ~= "testbed" then
                table.insert(keep, m)
            end
        end
        return keep
    end)
    return {}
end

--------------------------------------------------------------------------------
clink.argmatcher(
    "clink",
    "clink_x86.exe",
    "clink_x64.exe")
:addarg(
    "autorun"   .. autorun,
    "echo"      .. echo,
    "history"   .. history,
    "info"      .. nothing,
    "inject"    .. make_inject_parser():nofiles(),
    "update"    .. update,
    "installscripts" .. installscripts,
    "uninstallscripts" .. uninstallscripts,
    "set"       .. set,
    "drawtest"  .. drawtest,
    "testbed"   .. testbed,
    hide_tests)
:addflags("-h", "-p"..dir_matcher, "-~"..empty_arg, "-v", "-?")
:hideflags("-h", "-p", "-~", "-v", "-?")
:addflags(
    "--help",
    "--profile"..dir_matcher,
    "--session"..empty_arg,
    "--version")
:adddescriptions({
    ["--help"]      = "Show help",
    ["--profile"]   = { " dir", "Override the profile directory" },
    ["--session"]   = { " id", "Override the session id (for history and info)" },
    ["--version"]   = "Print Clink's version",
    ["autorun"]     = "Manage Clink's entry in cmd.exe's autorun",
    ["echo"]        = "Echo key sequences for use in .inputrc files",
    ["history"]     = "List and operate on the command history",
    ["info"]        = "Prints information about Clink",
    ["inject"]      = "Injects Clink into a process",
    ["update"]      = "Check for an update for Clink",
    ["installscripts"] = "Add a path to search for scripts",
    ["uninstallscripts"] = "Remove a path to search for scripts",
    ["set"]         = "Adjust Clink's settings"})
:nofiles()

--------------------------------------------------------------------------------
local set_generator = clink.generator(clink.argmatcher_generator_priority - 1)

function set_generator:generate(line_state, match_builder) -- luacheck: no self
    local first_word = clink.lower(path.getname(line_state:getword(1)))
    if path.getbasename(first_word) ~= "clink" and first_word ~= "clink_x64.exe" and first_word ~= "clink_x86.exe" then
        return
    end

    local index = 2
    while index < line_state:getwordcount() do
        local word = line_state:getword(index)
        if word == "--help" or word == "-h" or word == "-?" then -- luacheck: ignore 542
        elseif word == "--version" or word == "-v" then -- luacheck: ignore 542
        elseif word == "--profile" or word == "-p" then
            index = index + 1
        else
            break
        end
        index = index + 1
    end

    if line_state:getword(index) ~= "set" then
        return
    end

    index = index + 1
    while true do
        local word = line_state:getword(index)
        if word ~= "--help" and word ~= "-h" and word ~= "-?" and word ~= "--describe" and word ~= "-d" then
            break
        end
        index = index + 1
    end

    if index == line_state:getwordcount() then
        return
    end

    index = index + 1
    local matches = value_handler(line_state:getword(index), index, line_state)
    if matches then
        match_builder:addmatches(matches, "arg")
    end
    return true
end
