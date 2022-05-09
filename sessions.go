package sessions

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/ssh"
	yall "yall.in"
)

const (
	accessLength = 1 * time.Hour
)

var (
	// ErrInvalidToken is returned when parsing or validating a token that
	// is malformed or invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidSigningMethod is returned when parsing or validating a
	// token that claims to have been signed with an invalid signing
	// method.
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	// ErrUnknownSigningKey is returned when validating a token that claims
	// to have been signed by an unrecognized key.
	ErrUnknownSigningKey = errors.New("unknown signing key")
	tokenCtxKey          = ctxKey{}
)

type ctxKey struct{}

// AccessToken is a representation of a bearer token that authenticates a user
// when accessing a resource.
type AccessToken struct {
	// ID is a unique identifier for this access token.
	ID string
	// CreatedFrom identifies the grant this access token was created
	// using.
	CreatedFrom string
	// Scopes holds the scopes granted to this access token.
	Scopes []string
	// ProfileID identifies the profile this access token is for.
	ProfileID string
	// ClientID identifies the client that this token was granted to.
	ClientID string
	// CreatedAt identifies when this token was created.
	CreatedAt time.Time
}

// AccessTokenClaims is a set of claims can be associated with a JWT to yield a
// JWT that can be exchanged for an AccessToken.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scopes      []string `json:"scopes,omitempty"`
	CreatedFrom string   `json:"from,omitempty"`
}

// Dependencies are the
type Dependencies struct {
	// JWTPrivateKey is the private key that JWTs should be signed with.
	JWTPrivateKey *rsa.PrivateKey
	// JWTPublicKey is the public key that JWTs can be verified with.
	JWTPublicKey *rsa.PublicKey
	// ServiceID is a unique identifier for the service.
	ServiceID string
}

func getPublicKeyFingerprint(pk *rsa.PublicKey) (string, error) {
	p, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("Error creating SSH public key: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(p)
	return fingerprint, nil
}

// CreateJWT turns an AccessToken into a signed JWT.
func (d Dependencies) CreateJWT(_ context.Context, token AccessToken) (string, error) {
	res := jwt.NewWithClaims(jwt.SigningMethodRS256, AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{token.ClientID},
			ExpiresAt: jwt.NewNumericDate(token.CreatedAt.UTC().Add(accessLength)),
			ID:        token.ID,
			IssuedAt:  jwt.NewNumericDate(token.CreatedAt.UTC()),
			Issuer:    d.ServiceID,
			NotBefore: jwt.NewNumericDate(token.CreatedAt.UTC().Add(-1 * time.Hour)),
			Subject:   token.ProfileID,
		},
		Scopes:      token.Scopes,
		CreatedFrom: token.CreatedFrom,
	})
	fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
	if err != nil {
		return "", err
	}
	res.Header["kid"] = fp
	return res.SignedString(d.JWTPrivateKey)
}

// Validate parses jwtVal into an AccessToken, verifying that it has a good signature.
func (d Dependencies) Validate(ctx context.Context, jwtVal string) (AccessToken, error) {
	tok, err := jwt.ParseWithClaims(jwtVal, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningMethod, token.Header["alg"])
		}
		fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
		if err != nil {
			return nil, err
		}
		if fp != token.Header["kid"] {
			return nil, ErrUnknownSigningKey
		}
		return d.JWTPublicKey, nil
	})
	if err != nil {
		yall.FromContext(ctx).WithError(err).Debug("Error validating token.")
		return AccessToken{}, ErrInvalidToken
	}
	claims, ok := tok.Claims.(*AccessTokenClaims)
	if !ok {
		return AccessToken{}, ErrInvalidToken
	}
	if len(claims.Audience) < 1 {
		yall.FromContext(ctx).Error("No claim audience set.")
		return AccessToken{}, ErrInvalidToken
	}
	return AccessToken{
		ID:          claims.ID,
		CreatedFrom: claims.Issuer,
		ProfileID:   claims.Subject,
		ClientID:    claims.Audience[0],
		Scopes:      claims.Scopes,
		CreatedAt:   claims.IssuedAt.Time,
	}, nil
}

// TokenFromRequest returns an AccessToken from the http.Request's
// Authorization header, validating the signature on it. If the request has no
// Authorization header, a nil AccessToken is returned, signifying the request
// was not authenticated.
func (d Dependencies) TokenFromRequest(r *http.Request) (*AccessToken, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil //nolint:nilnil // this is actually more useful an API than a sentinel error
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, ErrInvalidToken
	}
	auth = strings.TrimPrefix(auth, "Bearer ")
	tok, err := d.Validate(r.Context(), auth)
	return &tok, err
}

// InContext injects the access token into the context.Context and returns a
// new, modified context.Context.
func InContext(ctx context.Context, token *AccessToken) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}

// FromContext returns the AccessToken in the context.Context, returning nil if
// no AccessToken is in the context.Context.
func FromContext(ctx context.Context) *AccessToken {
	t := ctx.Value(tokenCtxKey)
	if t == nil {
		return nil
	}
	tok, ok := t.(*AccessToken)
	if !ok {
		return nil
	}
	return tok
}
