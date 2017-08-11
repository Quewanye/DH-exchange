package dh_error
import(
	"errors"
	"fmt"
	"os"
)
var (
	ErrListen         = errors.New("can not listen this IP and port")
	ErrAccept         = errors.New("can not accept a connection")
	ErrRead           = errors.New("error in reading from socket")
	ErrSerializaton   = errors.New("error in serializaton")
	ErrUnserializaton = errors.New("error in unserializaton")
	ErrClose          = errors.New("client closed the connection")
	ErrResolvetcpAddr = errors.New("error in resolve tcp address")
	ErrConnect        = errors.New("error in connect to server")
	ErrInput          = errors.New("error in input")
)
	
func CheckError(err error) {
	if err != nil {
		fmt.Printf("Error : %s\n", err)
		if err != ErrClose {
			os.Exit(1)
		}
	}
}
