#!/bin/sh
# Usage: ./hb_stats.sh /path/to/logdir
#
# This script scans all files under the specified directory using `find`,
# extracts hackbench result lines in the form of "Time: X.XXX",
# collects the numeric values, and computes statistics:
#   - number of samples
#   - min / max
#   - mean
#   - median
#   - standard deviation
#
# The script is POSIX-compatible and works on BusyBox environments.

set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 /path/to/logdir" >&2
    exit 1
fi

LOGDIR="$1"

if [ ! -d "$LOGDIR" ]; then
    echo "Error: '$LOGDIR' is not a directory" >&2
    exit 1
fi

# Create temporary files
TMP_TIMES="$(mktemp)"
TMP_SORTED="$(mktemp)"

# Ensure temporary files are removed on exit
cleanup() {
    rm -f "$TMP_TIMES" "$TMP_SORTED"
}
trap cleanup EXIT

# Extract the numeric time values from all "Time:" lines under LOGDIR.
# Using -print0 and xargs -0 to handle filenames with spaces.
find "$LOGDIR" -type f -print0 \
  | xargs -0 grep -h "^Time:" 2>/dev/null \
  | awk '{print $2}' > "$TMP_TIMES"

# Number of samples
N=$(wc -l < "$TMP_TIMES" | tr -d ' ')

if [ "$N" -eq 0 ]; then
    echo "No 'Time:' lines found under $LOGDIR"
    exit 0
fi

# Sort numeric values to compute median, min, max
sort -n "$TMP_TIMES" > "$TMP_SORTED"

# Compute mean and standard deviation
MEAN_AND_STD=$(awk '
{
    sum += $1
    sumsq += $1 * $1
}
END {
    mean = sum / NR
    # Variance = E[X^2] - (E[X])^2
    var = (sumsq / NR) - (mean * mean)
    if (var < 0) var = 0   # protect against floating-point rounding error
    std = sqrt(var)
    printf "%.6f %.6f\n", mean, std
}
' "$TMP_TIMES")

MEAN=$(echo "$MEAN_AND_STD" | awk '{print $1}')
STDDEV=$(echo "$MEAN_AND_STD" | awk '{print $2}')

# Compute median
# If N is odd → median is the middle value
# If N is even → median = average of the two middle values
if [ $((N % 2)) -eq 1 ]; then
    POS=$(( (N + 1) / 2 ))
    MEDIAN=$(awk -v pos="$POS" 'NR == pos {printf "%.6f\n", $1}' "$TMP_SORTED")
else
    POS1=$(( N / 2 ))
    POS2=$(( N / 2 + 1 ))
    MEDIAN=$(awk -v p1="$POS1" -v p2="$POS2" '
        NR == p1 {v1 = $1}
        NR == p2 {v2 = $1}
        END {
            m = (v1 + v2) / 2.0
            printf "%.6f\n", m
        }
    ' "$TMP_SORTED")
fi

# Minimum and maximum values
MIN=$(head -n1 "$TMP_SORTED")
MAX=$(tail -n1 "$TMP_SORTED")

# Final summary
echo "Directory : $LOGDIR"
echo "Samples   : $N"
echo "Min       : $MIN"
echo "Max       : $MAX"
echo "Mean      : $MEAN"
echo "Median    : $MEDIAN"
echo "Stddev    : $STDDEV"
