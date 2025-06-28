# Unicast vs Anycast

## Summary

Unicast is preferred when you want maximum control,
predictability, and potentially lower latency, while
anycast is used as a fallback for global reachability and
redundancy. NextDNS tries unicast first for these reasons,
then falls back to anycast if unicast is unavailable.

## The Details

There is a preference for unicast routing over anycast
in the NextDNS endpoint selection for several reasons:

### Performance and Latency

Unicast routing allows the client to connect directly
to a specific, known server IP address. This can reduce
latency and avoid the unpredictability of anycast, where
the "nearest" node may not always be the fastest or most
reliable due to BGP routing quirks.

### Stability and Consistency

With unicast, the client always connects to the same
server, which can provide more consistent performance
and troubleshooting. Anycast can sometimes result in
the client being routed to different servers over time,
which may cause inconsistent behavior or performance.

### Advanced Features and Diagnostics

Some advanced features (like debugging, diagnostics, or
sticky sessions) may require a stable, direct connection
to a specific server, which unicast provides. Anycast, by
design, abstracts away the actual server being used.

### Avoiding Routing Loops or Suboptimal Paths

Anycast relies on global BGP routing, which can sometimes
result in suboptimal paths, routing loops, or even
blackholing if there are network issues. Unicast avoids
these issues by specifying the exact server IP.

### Control and Predictability

Unicast gives the service provider and the client more
control over which server is used, which is important for
debugging, compliance, or region-specific features.
