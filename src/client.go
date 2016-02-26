package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"crypto/x509"
	"bufio"
    "os"
    "encoding/xml"
    "io"
)
/////////////////////////////////////////////////////////////////////////////////xml struct
type info struct {
           XMLName xml.Name `xml:"info"`
           Version string `xml:"version"`
           CipherSuite string `xml:"cipherSuite"`
         }

         type infoSet struct {
           XMLName xml.Name `xml:"InfoSet"`
           Infos []info  `xml:"info"`
         }

////////////////////////////////////////////////////////////////////////////////////////////
func main() {


/////////////////////////////////////////////////////////////////////////////////////////mapping
	var findCipherSuite = map[uint16]string{
    tls.TLS_RSA_WITH_RC4_128_SHA:      `TLS_RSA_WITH_RC4_128_SHA`,
    tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`,
    tls.TLS_RSA_WITH_AES_128_CBC_SHA:  `TLS_RSA_WITH_AES_128_CBC_SHA` ,         
    tls.TLS_RSA_WITH_AES_256_CBC_SHA:   `TLS_RSA_WITH_AES_256_CBC_SHA` ,         
    tls.TLS_RSA_WITH_AES_128_GCM_SHA256:  `TLS_RSA_WITH_AES_128_GCM_SHA256` ,       
    tls.TLS_RSA_WITH_AES_256_GCM_SHA384:   `TLS_RSA_WITH_AES_256_GCM_SHA384` ,      
    tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:  `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` ,      
    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SH` ,   
    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:  `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` ,  
    tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: `TLS_ECDHE_RSA_WITH_RC4_128_SHA` ,         
    tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA` ,    
    tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:  `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` ,    
    tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` ,  
    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` ,
    tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` ,
    tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` ,
    tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` ,
}

var tlsVersion = map[uint16]string{
    tls.VersionSSL30: `VersionSSL30`,
    tls.VersionTLS10: `VersionTLS10`,
    tls.VersionTLS11: `VersionTLS11`,
    tls.VersionTLS12: `VersionTLS12`,
}

////////////////////////////////////////////////////////////////////////////////////////tcp connection part

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Ip (+ port) : ")
	targetIp, _ := reader.ReadString('\n')


	conn, err := tls.Dial("tcp", targetIp, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}

	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()

	
////////////////////////////////////////////////////////////////////////////////////certificate information

	for _, v := range state.PeerCertificates {
		fmt.Println("Server public key : ")
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
	}
    fmt.Println("\n")


    ////////////////////////////////////////////////////////////////////////////////////certificate information
    fmt.Println("Issuer : ", state.PeerCertificates[0].Issuer)
    fmt.Println("\n")
    fmt.Println("certificate validity.start : ", state.PeerCertificates[0].NotBefore)
    fmt.Println("\n")
    fmt.Println("certificate validity.end : ", state.PeerCertificates[0].NotAfter)
    fmt.Println("\n")
    fmt.Println("certificate KeyUsage : ", state.PeerCertificates[0].KeyUsage)
    fmt.Println("\n")
    fmt.Println("certificate ExtKeyUsage : ", state.PeerCertificates[0].ExtKeyUsage)
    fmt.Println("\n")
    fmt.Println("certificate BasicConstraintsValid : ", state.PeerCertificates[0].BasicConstraintsValid)
    fmt.Println("\n")
    fmt.Println("certificate SubjectKeyId : ", state.PeerCertificates[0].SubjectKeyId)
    fmt.Println("\n")
    fmt.Println("certificate AuthorityKeyId : ", state.PeerCertificates[0].AuthorityKeyId)
    fmt.Println("\n")
    fmt.Println("certificate OCSPServer : ", state.PeerCertificates[0].OCSPServer)
    fmt.Println("\n")
    fmt.Println("certificate IssuingCertificateURL : ", state.PeerCertificates[0].IssuingCertificateURL)
    fmt.Println("\n")
    fmt.Println("certificate DNSNames(subject) : ", state.PeerCertificates[0].DNSNames)
    fmt.Println("\n")
    fmt.Println("certificate EmailAddresses(subject): ", state.PeerCertificates[0].EmailAddresses)
    fmt.Println("\n")
    fmt.Println("certificate IPAddresses(subject) : ", state.PeerCertificates[0].IPAddresses)
    fmt.Println("\n")
    fmt.Println("certificate Signature  : ", state.PeerCertificates[0].Signature)
    fmt.Println("\n")
    fmt.Println("certificate Version  : ", state.PeerCertificates[0].Version)
    fmt.Println("\n")
	fmt.Println("certificate SerialNumber : ", state.PeerCertificates[0].SerialNumber)
    fmt.Println("\n")
	fmt.Println("certificate Subject : ", state.PeerCertificates[0].Subject)
    fmt.Println("\n")		
	fmt.Println("certificate SignatureAlgorithm : ", state.PeerCertificates[0].SignatureAlgorithm)
    fmt.Println("\n")
	fmt.Println("certificate PublicKeyAlgorithm: ", state.PeerCertificates[0].PublicKeyAlgorithm)
    fmt.Println("\n")


    ////////////////////////////////////////////////////////////////////////////////////////////connectionstate information
    fmt.Println("SSL Version : ", tlsVersion[state.Version])
    fmt.Println("\n")
	fmt.Println("Server cipher suite : ", findCipherSuite[state.CipherSuite])
    fmt.Println("\n")
	fmt.Println("VerifiedChains : ", state.VerifiedChains)
    fmt.Println("\n")
	
	
	/////////////////////////////////////////////////////////////////////////////make xml file
	  v := &infoSet{}

         v.Infos = append(v.Infos, info{Version: tlsVersion[state.Version], CipherSuite: findCipherSuite[state.CipherSuite]})
         
         filename := "Info.xml"
         file, _ := os.Create(filename)

         xmlWriter := io.Writer(file)

         enc := xml.NewEncoder(xmlWriter)
         enc.Indent("  ", "    ")
         if err := enc.Encode(v); err != nil {
                 fmt.Printf("error: %v\n", err)
         }
    /////////////////////////////////////////////////////////////////////////////////////////////////
         
}