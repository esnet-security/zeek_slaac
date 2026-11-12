# @TEST-EXEC: zeek -C -r $TRACES/slaac_ra.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut id.orig_h < conn.log > conn.tmp && mv conn.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
