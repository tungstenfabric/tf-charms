#!/bin/sh
MAX_AGE_MINS=70;
DUMP_FILE="$1";

if [ -z "$DUMP_FILE" ]; then
    echo "UNKNOWN. Specify a dumpfile. $0 <dumpfile>";
    exit 3;
fi

if [ ! -f "$DUMP_FILE" ]; then
    echo "WARN. Dump file not found: $DUMP_FILE";
    exit 1;
fi

find "$DUMP_FILE" -mmin "+$MAX_AGE_MINS" | grep -q .
if [ "$?" -eq 0 ]; then
    echo "WARN. Dump file not updated in the last $MAX_AGE_MINS minutes";
    exit 1;
fi

awk '
BEGIN {
    check_found=0;
}
/Checker check_/ && !/: Success/ {
    check_found=1;
    critical=1;
    print;
}
/Checker check_/ {
    check_found=1;
}
END {

    if(critical) {
        print "CRITICAL";
        exit 2;
    }
    else if(!check_found) {
        print "WARN. No checks found.";
        exit 1;
    }
    else {
        print "OK";
        exit 0;
    }
}
' "$DUMP_FILE";
