// This package describe a server communicate with client to negotiate a DH exchange session key.
// First, it will set up TCP connentions between server and client, then the server will share
// some DH parameters with client. Finally, server will calculate the session key which is used
// for encrypting/decrypting the later message.

package main

import (
	"./dhexchange"
	"encoding/json"
	"fmt"
	"net"
	"./dh_error"
)

var(
    RequestGP = 1
    RespondGP=2
    RespondCli_Pubk = 3
    RespondSer_Pubk = 4
    RespondCipherText = 5
    
)

// massage fomat: T_type, G, P, pub_key, msg
// type of T_type and infomation:
//		T_type=1: form client to server, request for parameters G, P
//		T_type=2: form server to client, response for parameters G, P
//		T_type=3: form client to server, obtain the public key of client
//		T_type=4: form server to client, obtain the public key of server
//		T_type=5: Ciphertext which encrypted with secret_key

func main() {
	listen, err := net.Listen("tcp", "localhost:8001")
	if err != nil {
		dh_error.CheckError(dh_error.ErrListen)
	}
	defer listen.Close()
	fmt.Println("waiting for clients")
	for {
		conn, err := listen.Accept()
		defer conn.Close()
		if err != nil {
			dh_error.CheckError(dh_error.ErrAccept)
		}
		fmt.Println(conn.RemoteAddr().String(), "tcp connect success")
		handleConnection(conn)
	}
}

//handle connection

func handleConnection(conn net.Conn) {
	var (
		G, P                 dhexchange.Uint128
		A_pub_key            dhexchange.Uint128
		b_pri_key, B_pub_key dhexchange.Uint128
		secret_key           dhexchange.Uint128
		req_msg              dhexchange.DH_pac
		get_msg              dhexchange.DH_pac
	)
	buffer := make([]byte, 2048)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			dh_error.CheckError(dh_error.ErrClose)
			break
		}
		err = json.Unmarshal(buffer[:n], &get_msg)
		if err != nil {
			dh_error.CheckError(dh_error.ErrUnserializaton)
		}
		switch get_msg.T_type {
		case RequestGP: // send parameters G and P
			G, P = dhexchange.Generate_G_P()
			req_msg.T_type = RespondGP
			req_msg.G = G
			req_msg.P = P
			req_msg.Msg = "send P G"
			fmt.Println("send P")
			fmt.Println(req_msg.P)
			fmt.Println("send G")
			fmt.Println(req_msg.G)

			message, err := json.Marshal(req_msg)
			if err != nil {
				dh_error.CheckError(dh_error.ErrSerializaton)
			}

			conn.Write(message)
			fmt.Println("send over")

		case RespondCli_Pubk: // get client's public key and send server's public key
			req_msg.T_type = RespondSer_Pubk
			b_pri_key, B_pub_key = dhexchange.Generate_pri_pub_key(G, P)
			A_pub_key = get_msg.A_pub_key
			req_msg.B_pub_key = B_pub_key
			req_msg.Msg = "server send public key"

			message, err := json.Marshal(req_msg)
			if err != nil {
				dh_error.CheckError(dh_error.ErrSerializaton)
			}

			conn.Write(message)
			fmt.Println("send server's public key")
			fmt.Println(" ")
			fmt.Println("send over")

		case RespondCipherText: // get ciphertext and decrypt it
			secret_key = dhexchange.Generate_secret_key(A_pub_key, b_pri_key, P)
			Ciphertext := get_msg.Ciphertext
			//fmt.Println(Ciphertext)
			plaintext, _ := dhexchange.AesDecrypt(Ciphertext, secret_key.Tobyte())
			fmt.Println("server get the plaintext:")
			fmt.Println(string(plaintext))
		}
	}
}

