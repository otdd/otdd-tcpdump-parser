package io.otdd.tcpdump.parser.tcp;

public enum ConnDirection {
    INCOMING,
    OUTGOING,
    UNKNOWN;

    public String toString() {
        if (this.ordinal() == INCOMING.ordinal()) {
            return "incoming";
        } else if (this.ordinal() == OUTGOING.ordinal()) {
            return "outgoing";
        } else {
            return "unknown";
        }
    }
}
