#!/usr/bin/env sh
# Measure the TCB: kernel lines, and how many sit inside `unsafe`.
#
# An unsafe line is any line from the start of an `unsafe` item or block through
# its closing brace; the `#[unsafe(...)]` attribute form does not count. Method is
# comment-stripped brace matching in awk: approximate at the edges (a `//` or a
# brace inside a string literal confuses it), so a measurement, not a proof.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="${1:-$ROOT/kernel/src}"

# One awk process, so the running totals in END are correct.
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
