#!/usr/bin/env sh
# Measure the TCB: how many lines of kernel there are, and how many of them sit
# inside `unsafe`.
#
# The project's claim is that "the TCB is N lines, M of them unsafe". That has to
# be measured rather than asserted. This is the measurement.
#
# What counts as an unsafe line: every line from the start of an `unsafe` item or
# block through its closing brace — `unsafe fn`, `unsafe impl`, `unsafe extern`,
# and `unsafe { }` blocks. The `#[unsafe(naked)]` / `#[unsafe(no_mangle)]`
# attribute form is *not* counted: it is a 2024-edition spelling of an attribute,
# not a region where the compiler stops checking.
#
# Method: comment-stripped brace matching in awk. It is approximate at the edges
# — a `//` inside a string literal, or a brace inside one, can confuse it — so
# treat the number as a good-faith measurement, not a proof. Blank lines and
# comment-only lines are excluded from both counts.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="${1:-$ROOT/kernel/src}"

# Paths here never contain spaces; keeping one awk process is what makes the
# running totals in END correct.
# shellcheck disable=SC2046
awk '
function report(file, total, unsafe_lines, regions) {
    printf "  %-28s %6d %8d %7d %8.1f%%\n", file, total, unsafe_lines, regions,
           (total ? unsafe_lines * 100.0 / total : 0)
}
BEGIN {
    printf "\n  %-28s %6s %8s %7s %9s\n", "file", "lines", "unsafe", "regions", "share"
    printf "  %-28s %6s %8s %7s %9s\n", \
        "----------------------------", "------", "--------", "-------", "---------"
}
FNR == 1 {
    if (NR > 1) report(shortname, f_total, f_unsafe, f_regions)
    shortname = FILENAME
    sub(/^.*\/kernel\//, "", shortname)
    f_total = 0; f_unsafe = 0; f_regions = 0
    in_unsafe = 0; depth = 0; opened = 0
}
{
    line = $0
    # The attribute spelling is not an unsafe region.
    gsub(/#\[unsafe\([A-Za-z_]*\)\]/, "", line)
    # Strip line comments and trailing whitespace.
    sub(/\/\/.*$/, "", line)
    sub(/[ \t]+$/, "", line)
    if (line ~ /^[ \t]*$/) next

    f_total++; total++

    if (!in_unsafe && line ~ /(^|[^A-Za-z0-9_])unsafe([^A-Za-z0-9_]|$)/) {
        in_unsafe = 1; depth = 0; opened = 0
    }

    if (in_unsafe) {
        f_unsafe++; unsafe_total++
        opens = gsub(/{/, "{", line)
        closes = gsub(/}/, "}", line)
        if (opens > 0) opened = 1
        depth += opens - closes
        if ((opened && depth <= 0) || (!opened && line ~ /;[ \t]*$/)) {
            in_unsafe = 0; f_regions++; regions++
        }
    }
}
END {
    report(shortname, f_total, f_unsafe, f_regions)
    printf "  %-28s %6s %8s %7s %9s\n", \
        "----------------------------", "------", "--------", "-------", "---------"
    report("TOTAL", total, unsafe_total, regions)
    printf "\n  TCB: %d lines, %d of them unsafe (%.1f%%), in %d regions.\n\n", \
        total, unsafe_total, (total ? unsafe_total * 100.0 / total : 0), regions
}
' $(find "$SRC" -name '*.rs' | sort)
