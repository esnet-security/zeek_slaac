# @TEST-EXEC: zeek -C -r $TRACES/slaac-na.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut id.orig_h target linklocal  message_type < slaac.log > slaac.tmp && mv slaac.tmp slaac.log
# @TEST-EXEC: btest-diff slaac.log
