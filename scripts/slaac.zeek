# Capture and Log IPv6 SLAAC assignments

module SLAAC;

export {
    redef enum Log::ID += { SLAAC_LOG };

    type SlaacInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        linklocal: bool &default=F &log;
        message_type: string &log;  # right now it's all NA's
        mac: string &log;
        override: bool &default=F &log;
        prefix: subnet &log;
        router: bool &default=F &log;
        solicited: bool &default=F &log;
        target: addr &log;
    };

    # Link Local
    const fe80: subnet = [fe80::]/10;
}

event zeek_init(){
    Log::create_stream(SLAAC::SLAAC_LOG, Log::Stream($columns=SlaacInfo, $path="slaac"));
}

function ipv6_to_padded_string(ip: addr): string {
    local c = addr_to_counts(ip);

    return fmt("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
        (c[0] >> 16) & 0xffff, c[0] & 0xffff,
        (c[1] >> 16) & 0xffff, c[1] & 0xffff,
        (c[2] >> 16) & 0xffff, c[2] & 0xffff,
        (c[3] >> 16) & 0xffff, c[3] & 0xffff);
}

function is_eui(orig: addr): bool{
    local d = addr_to_counts(orig);

    # Look for 0xFFFE indicating a MAC derived EUI-64
    # This is the original SLAAC specification and not normally used anymore, but useful if it's there
    if(d[2] & 0x00ff == 0x00ff && d[3] >> 16 & 0xff00 == 0xfe00){
        return T;
    }
    return F;    
}

function mac_from_eui(eui: addr): string {
    # The last 64bits of the address are the EUI-64 Interface Identifier
    # In most cases, we can convert back to the MAC address of the client

    local parts: vector of string = split_string(ipv6_to_padded_string(eui),/:/);
    local flip: count;
    local mac: string = "";

    # Flip back the 7th bit of the EUI-64
    flip = bytestring_to_count(hexstr_to_bytestring(parts[4]));
    flip = flip ^ (1 << 9);  # shift = 16-7
    parts[4] = fmt("%04x",flip);

    # Remove the extra 0xFFFE in the middle as well
    mac = fmt("%s:%s:%s:%s:%s:%s",parts[4][0:2],parts[4][2:4],parts[5][0:2]
                                ,parts[6][2:4],parts[7][0:2],parts[7][2:4]);

    return mac;
}

event icmp_router_advertisement(c: connection, info: icmp_info, cur_hop_limit: count, managed: bool, other: bool,
                                home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval,
                                reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options){
    local slaac_info: SLAAC::SlaacInfo;
    slaac_info$ts = c$conn$ts;
    slaac_info$uid = c$conn$uid;
    slaac_info$id = c$conn$id;
    slaac_info$message_type = "ra";
    slaac_info$router = T;

    if(c$id$orig_h in fe80){
        slaac_info$linklocal = T;
    }

    for (o in options){
        if (options[o]$otype == 3){
            slaac_info$prefix = to_subnet(fmt("%s/%s",options[o]$prefix$prefix,options[o]$prefix$prefix_len));
        }
    }
    Log::write(SLAAC::SLAAC_LOG, slaac_info);
}

event icmp_router_solicitation(c: connection, info: icmp_info, options: icmp6_nd_options){
    local slaac_info: SLAAC::SlaacInfo;

    slaac_info$ts = c$conn$ts;
    slaac_info$uid = c$conn$uid;
    slaac_info$id = c$conn$id;
    slaac_info$message_type = "rs";
    slaac_info$router = T;

    if(c$id$orig_h in fe80){
        slaac_info$linklocal = T;
    }

    Log::write(SLAAC::SLAAC_LOG, slaac_info);
}

event icmp_neighbor_advertisement(c: connection, info: icmp_info, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options){
    local slaac_info: SLAAC::SlaacInfo;

    slaac_info$ts = c$conn$ts;
    slaac_info$uid = c$conn$uid;
    slaac_info$id = c$conn$id;
    slaac_info$message_type = "na";
    slaac_info$override = override;
    slaac_info$router = router;
    slaac_info$solicited = solicited;
    slaac_info$target = tgt;

    if(c$id$orig_h in fe80){
        slaac_info$linklocal = T;
    }

    if(is_eui(c$id$orig_h)){
        slaac_info$mac = mac_from_eui(c$id$orig_h);
    }
    Log::write(SLAAC::SLAAC_LOG, slaac_info);

}

event icmp_neighbor_solicitation(c: connection, info: icmp_info, tgt: addr, options: icmp6_nd_options){
    local slaac_info: SLAAC::SlaacInfo;

    slaac_info$ts = c$conn$ts;
    slaac_info$uid = c$conn$uid;
    slaac_info$id = c$conn$id;
    slaac_info$message_type = "ns";
    slaac_info$target = tgt;

    if(c$id$orig_h in fe80){
        slaac_info$linklocal = T;
    }

    if(is_eui(c$id$orig_h)){
        slaac_info$mac = mac_from_eui(c$id$orig_h);
    }

    Log::write(SLAAC::SLAAC_LOG, slaac_info);
}