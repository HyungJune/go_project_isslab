package main

import (
	"crypto/rand"
	//"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"my-tls"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)

	}
	certpool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		log.Fatalf("Failed to read client certificate authority: %v", err)
	}
	if !certpool.AppendCertsFromPEM(pem) {
		log.Fatalf("Can't parse client certificate authority")
	}

	/*config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certpool,
	}*/

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		OnClientHello: func(clientHello *tls.ClientHello) {


			log.Printf("client version: %d", clientHello.Vers)
			log.Printf("client SNI: %s", clientHello.ServerName)

			for _, cipherSuiteId := range clientHello.CipherSuites {
				log.Printf("client cipher suite: (0x%04x)",cipherSuiteId)
			}

			for _, curveId := range clientHello.SupportedCurves {
				log.Printf("client curve: (%d)", curveId)
			}

			for _, pointId := range clientHello.SupportedPoints {
				log.Printf("client point: (%d)", pointId)
			}
		},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certpool,
	}








	config.Rand = rand.Reader
	service := "0.0.0.0:8000"
	listener, err := tls.Listen("tcp", service, config)


	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	tlscon, ok := conn.(*tls.Conn)
	if ok {
		log.Print("server: conn: type assert to TLS succeedded")
		err := tlscon.Handshake()
		if err != nil {
			log.Fatalf("server: handshake failed: %s", err)
		} else {
			log.Print("server: conn: Handshake completed")
		}



		state := tlscon.ConnectionState()


		log.Printf("SSL version = %d", state.Version)
		log.Printf("CipherSuite = %d", state.CipherSuite)

		/*buf := make([]byte, 512)
		for {
			log.Print("server: conn: waiting")
			n, err := conn.Read(buf)
			if err != nil {
				if err != nil {
					log.Printf("server: conn: read: %s", err)
				}
				break

			}
			log.Printf("server: conn: echo %q\n", string(buf[:n]))
			n, err = conn.Write(buf[:n])
			log.Printf("server: conn: wrote %d bytes", n)
			if err != nil {
				log.Printf("server: write: %s", err)
				break
			}
		}*/
	}
	log.Println("server: conn: closed")
}
