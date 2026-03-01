class CustomNetworkPacket:
    source_ip 
    source_port
    destination_ip 
    destination_port
    transport_protocol - udp / tcp
    bittorrent_protocol - bittorrent handshake, dht, tracker --??
    type_of_packet - dht , tracker http/udp, pwp, pex

    payload_dict -
                {
                    type: dht
                    msg_type: query, response, error
                    msg: ping, find_node, get_peers, announce_peers
                    msg_dict :
                        ping Query = {"t":"aa", "y":"q", "q":"ping", "a":{"id":"abcdefghij0123456789"}}
                        bencoded = d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe
                        Response = {"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}
                        bencoded = d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re

                        find_node Query = {"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456"}}
                        bencoded = d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe
                        Response = {"t":"aa", "y":"r", "r": {"id":"0123456789abcdefghij", "nodes": "def456..."}}
                        bencoded = d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re

                        get_peers Query = {"t":"aa", "y":"q", "q":"get_peers", "a": {"id":"abcdefghij0123456789", "info_hash":"mnopqrstuvwxyz123456"}}
                        bencoded = d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe
                        Response with peers = {"t":"aa", "y":"r", "r": {"id":"abcdefghij0123456789", "token":"aoeusnth", "values": ["axje.u", "idhtnm"]}}
                        bencoded = d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re
                        Response with closest nodes = {"t":"aa", "y":"r", "r": {"id":"abcdefghij0123456789", "token":"aoeusnth", "nodes": "def456..."}}
                        bencoded = d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re

                        announce_peers Query = {"t":"aa", "y":"q", "q":"announce_peer", "a": {"id":"abcdefghij0123456789", "implied_port": 1, "info_hash":"mnopqrstuvwxyz123456", "port": 68
                        bencoded = d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe
                        Response = {"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}
                        bencoded = d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
                }
    {
    


}





class NetworkPacket:
    source_ip 
    destination_ip 
    has_info_hash 
    

class BitTorrentPacket:
    net_packet 
    info_hash 
    bittorrent_metadata 

    
