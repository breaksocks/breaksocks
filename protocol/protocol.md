# freesocks protocol spec

## packet encrypt
1. before authenticated: encrypted by configured password or not encrypted
    1. packet flag: "genc"
    2. packet start with a size[2 bytes]
2. authenticated: encrypted by temporary password
    1. packet flag: "tenc"

## some packets
### 1. Startup Request (genc)
1. magic[1] : magic
2. session_size[1] : size of session id, 0 for a new session
3. random_size[1] : size of random data
4. hmac_size[1] : size of hmac result
5. session[session_size] : session id
6. random_data[random_size] : random data for hmac
7. hmac[hamac_size] : hmac(cipher, random_data)


### 2. Startup Response (genc)
1. new session response (start cipher exchange):
    1. pub_size[2] : size of pub
    2. p_size[2] : size of p
    3. f_size[2] : size of f
    4. sig_size[2] : size of signature
    5. pub[pub_size] : server public key
    6. p[p_size] : Diffie-Hellman-KeyExchange-Algorithm - p
    7. g[1] : Diffie-Hellman-KeyExchange-Algorithm - g
    8. f[f_size] : Diffie-Hellman-KeyExchange-Algorithm - f
    9. sig[sig_size] : signature of hash(p + g + f)
2. reuse session response(start ok or start exchange):
    1. resuse_ok[1] : whether login ok
    2. fail_code:[1] : reuse fail code
    3. cipher_exchange_init[?] : only if it can start cipher exchanging

### 3. Cipher Exchange Finish (genc)
1. e[size] : Diffie-Hellman-KeyExchange-Algorithm - e
2. [optional] Login Request encrypted packet (not encrypted by genc)

### 4. Encrypted Packet (tenc)
1. magic[1] : magic
2. packet_type[1] : packet type of encrypted data
3. packet_size[2] : size of packet
4. packet_data[packet_size] : real packet

### 5. Login Request(in Encrypted Packet)
1. client_version[2] : client protocol version
2. username_size[1] : size of username
3. passwd_size[1] : size of password
4. username[username_size] : username
5. passwd[passwd_size] : password

### 6. Login Response (in Encrypted Packet)
1. server_version[2] : server protocol version
2. login_ok[1] : is login ok (if login_ok is True the next field is session_size)
3. session_size[1] / errmsg_size : size of session id / login error message
4. session[session_size] / errmsg[errmsg_size] : session id / login error message

### 7. New Connection (in Encrypted Packet)
1. session_size[1] : size of session
2. conn_type[1] : (IPv4/6/unknown)[high 4bit] | (TCP/UDP/DOMAIN)[low 4bit]
3. port[2] : port
4. reserved[1] : reserved field
4. addr_size[1] : size of address
5. client_size[2] : client packet
6. addr[addr_size] : address to connect
7. client[client_size] : client packet that has sent

### 8. New Connection Response (in Encrypted Packet)
1. conn_id[4] : connection id
2. code[2] : error code
3. rep_size[2] : size of remote response
4. rep[rep_size] : remote packet that has sent

### 9. Packet Proxy (in Encrypted Packet)
1. conn_id[4] : connection id
2. data[determined by parent packet] : packet data

### 10. Close Connection (in Encrypted Packet)
1. conn_id[4] : connection id

