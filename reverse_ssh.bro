@load base/protocols/ssh

redef SSH::disable_analyzer_after_detection = F;

redef enum Notice::Type += {SSH_Reverse_Shell};

global ssh_conns:table[string] of count &redef;
global tunnelDetectedConns: set[string];
global sshExpectedBytes: table[string] of int; # Tracking uid == expected byte count for single keystroke inside a tunnel for this connection

global cipherSizeTable = table (
    ["chacha20-poly1305@openssh.com"] = 8 # Only reflecting chacha20 at this time as it's an outlier using 8 byte block sizes instead of 16; could add all other ciphers for sanity's sake.
);

global macSizeTable = table (
    ["hmac-sha1"] = 20,
    ["hmac-sha1-96"] = 12,
    ["hmac-sha2-256"] = 32,
    ["hmac-sha2-512"] = 64,
    ["hmac-md5"] = 16,
    ["hmac-md5-96"] = 12,
    ["umac-64@openssh.com"] = 8,
    ["umac-128@openssh.com"] = 16,
    ["hmac-sha1-etm@openssh.com"] = 20,
    ["hmac-sha1-96-etm@openssh.com"] = 12,
    ["hmac-sha2-256-etm@openssh.com"] = 32,
    ["hmac-sha2-512-etm@openssh.com"] = 64,
    ["hmac-md5-etm@openssh.com"] = 16,
    ["hmac-md5-96-etm@openssh.com"] = 12,
    ["umac-64-etm@openssh.com"] = 8,
    ["umac-128-etm@openssh.com"] = 16
);

const SINGLE_KEYSTROKE_BYTES = 1; # Num of bytes of a single keystroke; this is effectively the payload
const NON_ETM_MAC_PAYLOAD_LENGTH = 4; # 4 bytes because the length is encrypted in a uint32 field
const ETM_MAC_PAYLOAD_LENGTH = 1; # 1 byte since the length is plaintext
const MINIMUM_PADDING_PER_RFC = 4; # RFC requires a minimum padding of 4 bytes.


function calculatePacketLength(payloadLength: int, cipher_alg: string, mac_alg: string, etm: bool) : int{
    local cipherBlockSize = 16; # Default to 16
    local macBlockSize = 16; # Default to 16
    
    payloadLength = 1 + 1 + 4 + 4 + payloadLength; # 1 byte for the SSH_MESSAGE_CHANNEL (ByteField), 4 bytes for the Recipient Channel (uint32 field), 4 bytes for String Length (uint32 field)
    
    # In non-etm MACs the length field is encrypted and considered part of the payload
    if(!etm){
        payloadLength += NON_ETM_MAC_PAYLOAD_LENGTH;
    }
    
    # figure out the blocksize, this is used to determine padding
    if(cipher_alg in cipherSizeTable){
        cipherBlockSize = cipherSizeTable[cipher_alg];
    }
    
    # get the MAC length
    if(mac_alg in macSizeTable){
        macBlockSize = macSizeTable[mac_alg];
    }
    
    if( /poly1305/ in cipher_alg || /gcm/ in cipher_alg){
        macBlockSize = 16; # poly1305 and GCM in cipher overrides/ignores mac_alg field.
    }
    
    local packetCalc = +cipherBlockSize - payloadLength;
    local numBlocks = 1;
    
    # Calculate number of blocks needed based on the Cipher Blocksize
    while(packetCalc < 0){
        numBlocks += 1;
        packetCalc = packetCalc + cipherBlockSize;
    }
    
    local lengthCalc = (cipherBlockSize * numBlocks) - payloadLength; # Calculate how much padding is needed.
    

    # if the padding length is under the RFC requirement, than we're going to have to add an entire other block
    if(lengthCalc < MINIMUM_PADDING_PER_RFC){
        numBlocks += 1;
    }
    
    # Calculate length of payload with padding
    local payloadSize = cipherBlockSize * numBlocks;

    # ETM MAC's have the length field outside of the encrypted payload, therefore the bytes for this field are added after the padding calculation. 
    if(etm){
        payloadSize += 4;
    }

    return payloadSize + macBlockSize;
    
}


event ssh_auth_result(c: connection, result: bool, auth_attempts: count){
  local etm = /etm/ in c$ssh$mac_alg;

  if ( c$uid !in ssh_conns ) {
	ssh_conns[c$uid] = 0;
  }

  local originalPayloadLength = calculatePacketLength(SINGLE_KEYSTROKE_BYTES, c$ssh$cipher_alg, c$ssh$mac_alg, etm); # Calculate "normal" ssh connection length in bytes
    
  local sshTunnelPayloadLength = calculatePacketLength(originalPayloadLength, c$ssh$cipher_alg, c$ssh$mac_alg, etm); # Calculate totality of bytes including inside connection
        
  sshExpectedBytes[c$uid] = sshTunnelPayloadLength;

}


event ssh_encrypted_packet(c:connection, orig:bool, len:count){

  if(c$uid !in sshExpectedBytes) { return; }

  if ( orig == F && len == sshExpectedBytes[c$uid] && ssh_conns[c$uid] == 0 ){
    ssh_conns[c$uid] += 1;
    return;
  }

  if ( orig == T && len == sshExpectedBytes[c$uid] && ssh_conns[c$uid] == 1 ){
  	ssh_conns[c$uid] += 1;
    return;
  }

  if ( orig == F && len == sshExpectedBytes[c$uid] && ssh_conns[c$uid] >= 2 ){
    ssh_conns[c$uid] += 1;
    return;
  }

  if ( orig == T && len == sshExpectedBytes[c$uid] && ssh_conns[c$uid] >= 3 ){
    ssh_conns[c$uid] += 1;
    return;
  }

  if ( orig == T && len > sshExpectedBytes[c$uid] && ssh_conns[c$uid] >= 10 ){
    ssh_conns[c$uid] += 1;
    add tunnelDetectedConns[c$uid];
  }

  else { ssh_conns[c$uid] = 0; return; }

  if ( c$uid in tunnelDetectedConns ) {
    local char = ((ssh_conns[c$uid] / 2) - 1);
    NOTICE([$note=SSH_Reverse_Shell,
      $conn = c,
      $msg = fmt("Active SSH Reverse Shell from Host: %s to Host: %s:%s", c$id$orig_h,c$id$resp_h,c$id$resp_p),
      $sub = fmt("%s characters typed into a reverse SSH shell followed by a return.", char)
    ]);

    delete tunnelDetectedConns[c$uid];
    ssh_conns[c$uid] = 0;
  
  }
}
