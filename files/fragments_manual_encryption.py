#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import rc4
import zlib
import binascii

# Debut de l'algorithme
if __name__ == '__main__':

    # Donnees à chiffrer
    plaintext0 = "Un petit message "
    plaintext1 = "Un autre petit message"
    plaintext2 = "Et encore un autre"

    frameIndex = 0
    fragments = [plaintext0, plaintext1, plaintext2]

    # Cle wep de 5 bytes AA:AA:AA:AA:AA
    key = '\xaa\xaa\xaa\xaa\xaa'

    # Trame de départ pour avoir le template
    arp = rdpcap('arp.cap')[0]

    for fragment in fragments:
        # La seed est composé de IV + clé
        seed = arp.iv + key

        # Calcul de l'ICV
        icv = zlib.crc32(fragment)
        icv_clair = struct.pack('<i', icv)

        # on concatene l'icv et le plaintext
        fragment = fragment + icv_clair

        # Chiffrement par RC4
        ciphertext = rc4.rc4crypt(fragment, seed)

        # Prepare les datas
        arp.wepdata = ciphertext[:-4]
        (arp.icv,) = struct.unpack('!L', ciphertext[-4:])
        arp.SC = frameIndex
        frameIndex += 1

        if frameIndex == (len(fragments) - 1):
            # FC Field pour le dernier bit - Lors du dernier fragment, bit à 0
            arp.FCfield = arp.FCfield and 0x4

        # Write packet to a pcap file
        wrpcap('fragmentsWepEncrypted.cap', arp, append=True)
