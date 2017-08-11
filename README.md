# DH-exchange
  This project describe a server communicate with client to negotiate a DH exchange session key and use AES to encrypt and decrypt the message between server and client.
  First, it will set up TCP connentions between server and client, then the server and the client will share some DH parameters with eachother. Finally, they will calculate the session key which is usedfor encrypting/decrypting the later message.
