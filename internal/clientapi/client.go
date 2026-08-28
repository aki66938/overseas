package clientapi

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/agent"
)

const ErrorUnauthorized = "account_unauthorized"

var (
	ErrServiceUnavailable   = errors.New("overseas access service unavailable")
	ErrRequestID            = errors.New("request ID generation failed")
	ErrResponseTooLarge     = errors.New("named-pipe response exceeded size limit")
	ErrInvalidResponseShape = errors.New("named-pipe response shape is invalid")
	ErrMismatchedResponseID = errors.New("named-pipe response ID does not match request")
	ErrInvalidResponseState = errors.New("named-pipe response state is not approved")
	ErrInvalidResponseCode  = errors.New("named-pipe response error code is not approved")
)

type Status struct {
	State     accessmodel.ConnectionState `json:"state"`
	ErrorCode string                      `json:"error_code,omitempty"`
	Message   string                      `json:"message,omitempty"`
}

type Diagnostics struct {
	State      accessmodel.ConnectionState `json:"state"`
	ErrorCode  string                      `json:"error_code,omitempty"`
	Message    string                      `json:"message,omitempty"`
	Generation uint64                      `json:"generation"`
}

type dialPipeFunc func(context.Context, string) (net.Conn, error)
type requestIDFunc func() (string, error)

type Option func(*Client)

type Client struct {
	dialPipe         dialPipeFunc
	requestIDFactory requestIDFunc
}

func New(options ...Option) *Client {
	client := &Client{
		dialPipe:         defaultDialPipe,
		requestIDFactory: newRequestID,
	}
	for _, option := range options {
		option(client)
	}
	return client
}

func WithDialPipe(dialer func(context.Context, string) (net.Conn, error)) Option {
	return func(client *Client) {
		if dialer != nil {
			client.dialPipe = dialer
		}
	}
}

func WithRequestIDGenerator(generator func() (string, error)) Option {
	return func(client *Client) {
		if generator != nil {
			client.requestIDFactory = generator
		}
	}
}

func (c *Client) Connect(ctx context.Context) (Status, error) {
	return c.requestStatus(ctx, agent.ActionConnect)
}

func (c *Client) Disconnect(ctx context.Context) (Status, error) {
	return c.requestStatus(ctx, agent.ActionDisconnect)
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	return c.requestStatus(ctx, agent.ActionStatus)
}

func (c *Client) Diagnostics(ctx context.Context) (Diagnostics, error) {
	response, err := c.request(ctx, agent.ActionDiagnostics)
	if err != nil {
		return Diagnostics{}, err
	}
	diagnostics, err := decodeDiagnosticsMessage(response.Message)
	if err != nil {
		return Diagnostics{}, err
	}
	if response.State != string(diagnostics.State) || response.ErrorCode != diagnostics.ErrorCode {
		return Diagnostics{}, ErrInvalidResponseShape
	}
	return diagnostics, nil
}

func FormatDiagnostics(diagnostics Diagnostics) string {
	data, err := json.Marshal(diagnostics)
	if err != nil {
		return `{"state":"failed","error_code":"invalid_diagnostics","message":"诊断信息不可用","generation":0}`
	}
	return string(data)
}

func (c *Client) requestStatus(ctx context.Context, action string) (Status, error) {
	response, err := c.request(ctx, action)
	if err != nil {
		return Status{}, err
	}
	return Status{
		State:     accessmodel.ConnectionState(response.State),
		ErrorCode: response.ErrorCode,
		Message:   response.Message,
	}, nil
}

func (c *Client) request(ctx context.Context, action string) (agent.Response, error) {
	if c == nil {
		return agent.Response{}, fmt.Errorf("%w: client is nil", ErrServiceUnavailable)
	}
	requestID, err := c.requestIDFactory()
	if err != nil {
		return agent.Response{}, fmt.Errorf("%w: %v", ErrRequestID, err)
	}
	requestContext, cancel := context.WithTimeout(ctx, agent.PipeOperationTimeout)
	defer cancel()

	connection, err := c.dialPipe(requestContext, agent.PipeName)
	if err != nil {
		return agent.Response{}, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadlineFromContext(requestContext)); err != nil {
		return agent.Response{}, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}

	request := agent.Request{ID: requestID, Action: action}
	frame, err := json.Marshal(request)
	if err != nil {
		return agent.Response{}, err
	}
	if len(frame)+1 > agent.MaxPipeFrameBytes {
		return agent.Response{}, ErrInvalidResponseShape
	}
	if _, err := connection.Write(append(frame, '\n')); err != nil {
		return agent.Response{}, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}

	responseFrame, err := readResponseFrame(connection)
	if err != nil {
		return agent.Response{}, err
	}
	response, err := decodeResponse(responseFrame)
	if err != nil {
		return agent.Response{}, err
	}
	if response.ID != requestID {
		return agent.Response{}, ErrMismatchedResponseID
	}
	if !isApprovedState(response.State) {
		return agent.Response{}, ErrInvalidResponseState
	}
	if !isApprovedErrorCode(response.ErrorCode) {
		return agent.Response{}, ErrInvalidResponseCode
	}
	return response, nil
}

func readResponseFrame(connection net.Conn) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(connection, agent.MaxPipeFrameBytes+1))
	frame, err := reader.ReadBytes('\n')
	if len(frame) > agent.MaxPipeFrameBytes {
		return nil, ErrResponseTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServiceUnavailable, err)
	}
	if len(frame) == 0 || frame[len(frame)-1] != '\n' {
		return nil, ErrInvalidResponseShape
	}
	return frame[:len(frame)-1], nil
}

func decodeResponse(frame []byte) (agent.Response, error) {
	var response agent.Response
	decoder := json.NewDecoder(strings.NewReader(string(frame)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return agent.Response{}, ErrInvalidResponseShape
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return agent.Response{}, ErrInvalidResponseShape
	}
	return response, nil
}

func decodeDiagnosticsMessage(message string) (Diagnostics, error) {
	var diagnostics Diagnostics
	decoder := json.NewDecoder(strings.NewReader(message))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&diagnostics); err != nil {
		return Diagnostics{}, ErrInvalidResponseShape
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Diagnostics{}, ErrInvalidResponseShape
	}
	if !isApprovedState(string(diagnostics.State)) {
		return Diagnostics{}, ErrInvalidResponseState
	}
	if !isApprovedErrorCode(diagnostics.ErrorCode) {
		return Diagnostics{}, ErrInvalidResponseCode
	}
	return diagnostics, nil
}

func newRequestID() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func isApprovedState(state string) bool {
	switch accessmodel.ConnectionState(state) {
	case accessmodel.StateDisconnected, accessmodel.StateConnecting, accessmodel.StateConnected, accessmodel.StateFailed:
		return true
	default:
		return false
	}
}

func isApprovedErrorCode(code string) bool {
	switch code {
	case "",
		agent.ErrorInvalidAction,
		agent.ErrorInvalidRequest,
		agent.ErrorInvalidPolicy,
		agent.ErrorInvalidBinary,
		agent.ErrorCredential,
		agent.ErrorExpiredCredential,
		agent.ErrorNetworkCapture,
		agent.ErrorPublicTCPBlock,
		agent.ErrorRender,
		agent.ErrorCoreStart,
		agent.ErrorCoreNotReady,
		agent.ErrorRouteActivationFailed,
		agent.ErrorReadinessLost,
		agent.ErrorRestoreFailed,
		agent.ErrorCanceled,
		ErrorUnauthorized:
		return true
	default:
		return false
	}
}

func deadlineFromContext(ctx context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Now().Add(agent.PipeOperationTimeout)
	}
	return deadline
}
