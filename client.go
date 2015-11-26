package apns

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
	"bytes"
	"encoding/binary"
)

var _ APNSClient = &Client{}


//ERROR_CODES = {
//    1: ('Processing error', True, True),
//    2: ('Missing device token', True, False), # looks like token was empty?
//    3: ('Missing topic', False, True), # topic is encoded in the certificate, looks like certificate is wrong. bail out.
//    4: ('Missing payload', False, True), # bail out, our message looks like empty
//    5: ('Invalid token size', True, False), # current token has wrong size, skip it and retry
//    6: ('Invalid topic size', False, True), # can not happen, we do not send topic, it is part of certificate. bail out.
//    7: ('Invalid payload size', False, True), # our payload is probably too big. bail out.
//    8: ('Invalid token', True, False), # our device token is broken, skipt it and retry
//    10: ('Shutdown', True, False), # server went into maintenance mode. reported token is the last success, skip it and retry.
//    None: ('Unknown', True, True), # unknown error, for sure we try again, but user should limit number of retries
//}
var ErrorCanRetry = map[string]bool {
	ApplePushResponses[0]:	false,
	ApplePushResponses[1]:	true,
	ApplePushResponses[2]:	true,
	ApplePushResponses[3]:	true,
	ApplePushResponses[4]:	false,
	ApplePushResponses[5]:	true,
	ApplePushResponses[6]:	false,
	ApplePushResponses[7]:	false,
	ApplePushResponses[8]:	true,
	ApplePushResponses[10]:	true,
	ApplePushResponses[255]:	true,
}

var ErrorInclude = map[string]bool {
	ApplePushResponses[0]:	true,
	ApplePushResponses[1]:	true,
	ApplePushResponses[2]:	false,
	ApplePushResponses[3]:	true,
	ApplePushResponses[4]:	true,
	ApplePushResponses[5]:	false,
	ApplePushResponses[6]:	true,
	ApplePushResponses[7]:	true,
	ApplePushResponses[8]:	false,
	ApplePushResponses[10]:	false,
	ApplePushResponses[255]:	true,
}


// APNSClient is an APNS client.
type APNSClient interface {
	ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error)
	Send(pn *PushNotification) (resp *PushNotificationResponse)
}

// Client contains the fields necessary to communicate
// with Apple, such as the gateway to use and your
// certificate contents.
//
// You'll need to provide your own CertificateFile
// and KeyFile to send notifications. Ideally, you'll
// just set the CertificateFile and KeyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the CertificateBase64
// and KeyBase64 fields to store the actual contents.
type Client struct {
	Gateway           string
	CertificateFile   string
	CertificateBase64 string
	KeyFile           string
	KeyBase64         string
}

// BareClient can be used to set the contents of your
// certificate and key blocks manually.
func BareClient(gateway, certificateBase64, keyBase64 string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateBase64 = certificateBase64
	c.KeyBase64 = keyBase64
	return
}

// NewClient assumes you'll be passing in paths that
// point to your certificate and key.
func NewClient(gateway, certificateFile, keyFile string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateFile = certificateFile
	c.KeyFile = keyFile
	return
}

// Send connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (client *Client) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payload, err := pn.ToBytes()
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	err = client.ConnectAndWrite(resp, payload)
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	resp.Success = true
	resp.Error = nil

	return
}

// Send connects to the APN service and sends your push notifications.
// Remember that if the submission is successful, Apple won't reply.
func (client *Client) SendAll(pns []*PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payloads := []([]byte){}
	for _, pn:= range pns {
		payload, err := pn.ToBytes()
		if err != nil {
			resp.Success = false
			resp.Error = err
			return
		}
		payloads = append(payloads, payload)
	}

	var lastIdentifier int32 = -1
	err := client.ConnectAndWriteAll(resp, payloads)
	for err != nil {
		canRetry := ErrorCanRetry[resp.AppleResponse]
		include := ErrorInclude[resp.AppleResponse]
		identifier := resp.Identifier

		if canRetry {
			if include && identifier > lastIdentifier {
				err = client.ConnectAndWriteAll(resp, payloads[identifier:])
			} else {
				err = client.ConnectAndWriteAll(resp, payloads[identifier+1:])
			}
			lastIdentifier = resp.Identifier
		} else {
			resp.Success = false
			resp.Error = err
			return
		}
	}

	resp.Success = true
	resp.AppleResponse = ""
	resp.Error = nil

	return
}

// ConnectAndWrite establishes the connection to Apple and handles the
// transmission of your push notification, as well as waiting for a reply.
//
// In lieu of a timeout (which would be available in Go 1.1)
// we use a timeout channel pattern instead. We start two goroutines,
// one of which just sleeps for TimeoutSeconds seconds, while the other
// waits for a response from the Apple servers.
//
// Whichever channel puts data on first is the "winner". As such, it's
// possible to get a false positive if Apple takes a long time to respond.
// It's probably not a deal-breaker, but something to be aware of.
func (client *Client) ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error) {
	var cert tls.Certificate

	if len(client.CertificateBase64) == 0 && len(client.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(client.CertificateFile, client.KeyFile)
	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(client.CertificateBase64), []byte(client.KeyBase64))
	}

	if err != nil {
		return err
	}

	gatewayParts := strings.Split(client.Gateway, ":")
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   gatewayParts[0],
	}

	conn, err := net.Dial("tcp", client.Gateway)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	_, err = tlsConn.Write(payload)
	if err != nil {
		return err
	}

	// Create one channel that will serve to handle
	// timeouts when the notification succeeds.
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * TimeoutSeconds)
		timeoutChannel <- true
	}()

	// This channel will contain the binary response
	// from Apple in the event of a failure.
	responseChannel := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 6, 6)
		tlsConn.Read(buffer)
		responseChannel <- buffer
	}()


	// First one back wins!
	// The data structure for an APN response is as follows:
	//
	// command    -> 1 byte
	// status     -> 1 byte
	// identifier -> 4 bytes
	//
	// The first byte will always be set to 8.
	select {
	case r := <-responseChannel:
		resp.Success = false
		resp.AppleResponse = ApplePushResponses[r[1]]
		err = errors.New(resp.AppleResponse)
	case <-timeoutChannel:
		resp.Success = true
	}

	return err
}


func (client *Client) ConnectAndWriteAll(resp *PushNotificationResponse, payloads [][]byte) (err error) {
	var cert tls.Certificate

	if len(client.CertificateBase64) == 0 && len(client.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(client.CertificateFile, client.KeyFile)
	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(client.CertificateBase64), []byte(client.KeyBase64))
	}

	if err != nil {
		return err
	}

	gatewayParts := strings.Split(client.Gateway, ":")
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   gatewayParts[0],
	}

	conn, err := net.Dial("tcp", client.Gateway)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	for _, payload := range payloads {
		_, err = tlsConn.Write(payload)
		if err != nil {
			return err
		}
	}

	// Create one channel that will serve to handle
	// timeouts when the notification succeeds.
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * TimeoutSeconds)
		timeoutChannel <- true
	}()

	// This channel will contain the binary response
	// from Apple in the event of a failure.
	responseChannel := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 6, 6)
		tlsConn.Read(buffer)
		responseChannel <- buffer
	}()


	// First one back wins!
	// The data structure for an APN response is as follows:
	//
	// command    -> 1 byte
	// status     -> 1 byte
	// identifier -> 4 bytes
	//
	// The first byte will always be set to 8.
	select {
	case r := <-responseChannel:
		resp.Success = false
		resp.AppleResponse = ApplePushResponses[r[1]]

		err = binary.Read(bytes.NewBuffer(r[2:6]), binary.BigEndian, &resp.Identifier)
		if err != nil {
			return err
		}

		if resp.AppleResponse == ApplePushResponses[8] {
			resp.FaildTokenIdentifier = append(resp.FaildTokenIdentifier, resp.Identifier)
		}

		err = errors.New(resp.AppleResponse)
	case <-timeoutChannel:
		resp.Success = true
	}

	return err
}
