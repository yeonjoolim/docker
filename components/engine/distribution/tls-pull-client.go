package distribution

import (
    "crypto/tls"
    "crypto/x509"
    "io"
    "log"
    "os"
    "strconv"
    "net"
)

func TLS_client_pel(image_name string) bool{
    cert, err := tls.LoadX509KeyPair(dirPath+"dev2/dev2.crt", dirPath+"dev2/dev2.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
	return false
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
    conn, err := tls.Dial("tcp", "129.254.170.216:50000", &config)
    if err != nil {
        log.Fatalf("client: dial: %s", err)
	return false
    }
    defer conn.Close()
    log.Println("client: connected to: ", conn.RemoteAddr())

    state := conn.ConnectionState()
    for _, v := range state.PeerCertificates {
        x509.MarshalPKIXPublicKey(v.PublicKey)
    }
    log.Println("client: handshake: ", state.HandshakeComplete)
    log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
    
    buf := make([]byte, 40)

    var flag string = "2"
    _, err = io.WriteString(conn, flag)
    if err != nil {
	    log.Fatalf("client: write: %s", err)
	return false
    }
    log.Printf("client: conn: write: %s", flag)

    n, err := conn.Read(buf)
    if err != nil {
            log.Printf("server: conn: read: %x", err)
            _, err = io.WriteString(conn,"server read error")
	return false
    }

    var name string = image_name
    _, err = io.WriteString(conn,name)
    log.Printf("client: conn: write: %s", name)

    n, err = conn.Read(buf)
    if err != nil {
            log.Printf("server: conn: read: %s", err)
		return false            
    }

    if string(buf[:n]) == "OK"{
    	log.Printf("server: conn: read: %s", buf)
    }else{ 
    	log.Printf("server: conn: read: %s", buf)
	return false
    }

    _, err = io.WriteString(conn, "OK")

    n, err = conn.Read(buf)
    if err != nil {
            log.Printf("server: conn: read: %s", err)
        	return false    
    }

    str := string(buf[:n])
    size, _ := strconv.Atoi(str)
    log.Printf("client: conn: download %d size",size)

    _, err = io.WriteString(conn, "OK")
    if err != nil {
            _, _ = io.WriteString(conn, "download error")
        return false    
    }
    log.Printf("client: conn: write: %s", "OK")
 
    message := make([]byte, size)

    num := size / 1180 + 1
    log.Printf("Ready to receive %d sign data",num)
    message = Read_data(num,conn,size)

    filew(dirPath+name+"-resign.gob",message)

    _, err = io.WriteString(conn, "Receive Success")
    if err != nil {
            _, _ = io.WriteString(conn, "Receive fail")
        return false    
    }
    log.Printf("client: conn: write: %s", "Receive Success")

    log.Print("client: exiting")
	return true
}

func Read_data (num int, conn net.Conn, size int) []byte{
    m := make([][]byte, num)
    message := make([]byte,size)
    var n int
    for i:=0;i<num;i++{
        m[i] = make([]byte, 1180)
        n, _ = conn.Read(m[i])
        log.Printf("server: conn: read  %d size",n)
        if i > 0{
            message = append(message, m[i][:n]...)
        }else {
            message = append(message[:0:0], m[i][:n]...)
        }
    }
    return message
}


func filew(path string, data []byte) {
    fd, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0644))
    defer fd.Close()
    _,_ = fd.Write([]byte(data))
    log.Printf("Signed Data save complete!")
}

