import btdht
import binascii
dht = btdht.DHT()
dht.start()

dht.get_peers(binascii.a2b_hex("146e045d43bde19c75101a0bfd84bae4781c9686"))
