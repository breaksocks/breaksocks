# freesocks protocol spec

## packet encrypt
1. before authenticated: encrypted by configured password or not encrypted
    1. packet flag: "*genc"
2. authenticated: encrypted by temporary password
    1. packet flag: "*tenc"

## some packets
### 1. Startup Request (*genc)
1. rand_data_size[1] / session_size[1] : size of the rand data (postive) / old session (negative)
2. rand_data[rand_data_size] / session[session_size] : rand data / Reuse Session

### 2. Startup Response (*genc)
1. rand_data_size[1] / cipher_init_size[1] : size of rand data (negative) / cipher_exchange_init (postive)
2. rand_data[rand_data_size] / cipher_exchange_init : hmac_data / rand_data + cipher_exchange_init

### 3. Cipher Exchange Init (if start a new session, *genc)
1. pub_size[2] : size of pub
2. p_size[2] : size of p
3. f_size[2] : size of f
4. sig_size[2] : size of signature
5. pub[pub_size] : server public key
6. p[p_size] : Diffie-Hellman-KeyExchange-Algorithm - p
7. g[1] : Diffie-Hellman-KeyExchange-Algorithm - g
8. f[f_size] : Diffie-Hellman-KeyExchange-Algorithm - f
9. sig[sig_size] : signature of hash(p + g + f)

### 4. Login request (client continue cipher exchang and login)
1. e_size[2] : size of e
2. login_size[2] : size of login data
3. e[e_size] : Diffie-Hellman-KeyExchange-Algorithm - e
4. login_data[login_size] : login request (*tenc)
    1. maigc[1] : protocol magic
    2. client_version[1] : client protocol version
    3. username_size[1] : size of username
    4. passwd_size[1] : size of password
    5. username[username_size] : username
    6. passwd[passwd_size] : password

### 5. Login Response (finish cipher exchange and login response, *tenc)
1. magic[1] : protocol magic
2. server_version[1] : server protocol version
3. login_ok[1] : is login ok (if login_ok is True the next field is session_size)
4. session_size[1] / errmsg_size : size of session id / login error message
5. session[session_size] / errmsg[errmsg_size] : session id / login error message

### 6. Reuse Session (*genc)
1. session_size[1] : size of session id
2. random_size[1] : size of random data
3. hmac_size[1] : size of hmac result
4. session[session_size] : session id
5. random_data[random_size] : random data for hmac
6. hmac[hamac_size] : hmac(cipher, random_data)

### 7. Encrypted Packet (*tenc)
1. magic[1] : magic
2. packet type[1] : packet type of encrypted data
3. packet_size[2] : size of packet
4. packet data[packet_size] : real packet

### 8. New Connection (in Encrypted Packet)
1. session_size[1] : size of session
2. conn_type[1] : (IPv4/6/unknown)[high 4bit] | (TCP/UDP/DOMAIN)[low 4bit]
3. port[2] : port
4. addr_size[1] : size of address
5. client_size[2] : client packet
6. addr[addr_size] : address to connect
7. client[client_size] : client packet that has sent

### 9. New Connection Response (in Encrypted Packet)
1. conn_ok[1] : whether it is connected
2. conn_id[4] : connection id
3. rep_size[1] : size of remote response
4. rep[rep_size] : remote packet that has sent

### 10. Packet Proxy (in Encrypted Packet)
1. conn_id[4] : connection id
2. data[determined by parent packet] : packet data

### 11. Close Connection (encrypted)
1. conn_id[4] : connection id

## login / reuse session
### 1. new session
1. client send : Startup Request (with random data (postive size))
2. server send : Startup Response (with random data (postive size) and cipher_exchange_init)
3. client send : Login Request
4. server send : Login Response

### 2. reuse old session
1. client send : Startup Request (with Reuse Session (negative size))
2. server send : Startup Response (with rand data (negative size)
     or rand data (postive size) + cipher_exchange_init if fail)
3. if reuse fail, continue (new session).3

### 3. packet proxy
1. client send : New Connection
2. server send : New Connection Response
3. loop -> client / server send : Packet Proxy
4. when connection closed : Close Connection

