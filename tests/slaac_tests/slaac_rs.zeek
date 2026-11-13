# @TEST-EXEC: zeek -C -r $TRACES/slaac-rs.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.resp_h message_type < slaac.log > slaac.tmp && mv slaac.tmp slaac.log
# @TEST-EXEC: btest-diff slaac.log
