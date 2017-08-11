// This package describe a client communicate with server to negotiate a DH exchange session key.
// First, it will set up TCP connentions between client and server, then the client will share
// some DH parameters with server. Finally, client will calculate the session key which is used
// for encrypting/decrypting the later message.

package main

import (
	"./dhexchange"
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
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

func send(conn net.Conn, i int, G, P, A_pri_key, A_pub_key, secret_key *dhexchange.Uint128) {
	var req_msg dhexchange.DH_pac
	switch i {
	case RequestGP: // request for parameters G and P
		req_msg.T_type = RequestGP
		req_msg.Msg = "request for G, P"
		fmt.Println("client request for parameters G, P")

	case RespondCli_Pubk: // request for server's public key and send client's public key
		req_msg.T_type = RespondCli_Pubk

		*A_pri_key, *A_pub_key = dhexchange.Generate_pri_pub_key(*G, *P)
		req_msg.A_pub_key = *A_pub_key
		req_msg.Msg = "request for server's public key"
		fmt.Println("client send public key")

	case RespondCipherText: // send ciphertext
		req_msg.T_type = RespondCipherText

		readbuf := bufio.NewReader(os.Stdin)
		fmt.Println("input plaintext you want to send: ")
		plaintext, hasmore, errx := readbuf.ReadLine()

		if errx != nil || hasmore == true {
			dh_error.CheckError(dh_error.ErrInput)
		}

		Ciphertext, _ := dhexchange.AesEncrypt(plaintext, (*secret_key).Tobyte())
		req_msg.Ciphertext = Ciphertext
		fmt.Println("Ciphertext is:")
		fmt.Println(string(Ciphertext))
	}

	message, err := json.Marshal(req_msg)

	if err != nil {
		dh_error.CheckError(dh_error.ErrSerializaton)
	}
	conn.Write(message)
	fmt.Println("send over")
}

func read(conn net.Conn, G, P, A_pri_key, A_pub_key, B_pub_key, secret_key *dhexchange.Uint128) {
	buffer := make([]byte, 1024)
	var get_msg dhexchange.DH_pac
	n, err := conn.Read(buffer)
	if err != nil {
		dh_error.CheckError(dh_error.ErrRead)
	}

	err = json.Unmarshal(buffer[:n], &get_msg)
	if err != nil {
		dh_error.CheckError(dh_error.ErrUnserializaton)
	}

	switch get_msg.T_type {
	case RespondGP: // get parameters G and P
		*G = get_msg.G
		*P = get_msg.P
		fmt.Println("get G:")
		fmt.Println(*G)
		fmt.Println("get P:")
		fmt.Println(*P)

	case RespondSer_Pubk: // get server's public key
		*B_pub_key = get_msg.B_pub_key
		*secret_key = dhexchange.Generate_secret_key(*B_pub_key, *A_pri_key, *P)
	}
}

func main() {
	server := "127.0.0.1:8001"

	tcpAddr, err := net.ResolveTCPAddr("tcp4", server)
	if err != nil {
		dh_error.CheckError(dh_error.ErrResolvetcpAddr)
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	if err != nil {
		dh_error.CheckError(dh_error.ErrConnect)
	}
	fmt.Println("connect success")
	var G, P, A_pri_key, A_pub_key, B_pub_key, secret_key dhexchange.Uint128
	send(conn, 1, &G, &P, &A_pri_key, &A_pub_key, &secret_key)
	read(conn, &G, &P, &A_pri_key, &A_pub_key, &B_pub_key, &secret_key)
	time.Sleep(3 * time.Second)

	send(conn, 3, &G, &P, &A_pri_key, &A_pub_key, &secret_key)
	read(conn, &G, &P, &A_pri_key, &A_pub_key, &B_pub_key, &secret_key)
	time.Sleep(3 * time.Second)

	send(conn, 5, &G, &P, &A_pri_key, &A_pub_key, &secret_key)

}

