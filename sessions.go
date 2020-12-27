package sessions

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	jwt "github.com/dgrijalva/jwt-go"
	yall "yall.in"
)

const (
	accessLength = 1 * time.Hour
)

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	tokenCtxKey             = ctxKey{}
)

type ctxKey struct{}

type AccessToken struct {
	ID          string
	CreatedFrom string
	Scopes      []string
	ProfileID   string
	ClientID    string
	CreatedAt   time.Time
}

type AccessTokenClaims struct {
	jwt.StandardClaims
	Scopes      []string `json:"scopes,omitempty"`
	CreatedFrom string   `json:"from,omitempty"`
}

type Dependencies struct {
	JWTPrivateKey *rsa.PrivateKey
	JWTPublicKey  *rsa.PublicKey
	ServiceID     string
}

func getPublicKeyFingerprint(pk *rsa.PublicKey) (string, error) {
	p, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("Error creating SSH public key: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(p)
	return fingerprint, nil
}

func (d Dependencies) CreateJWT(ctx context.Context, token AccessToken) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, AccessTokenClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  token.ClientID,
			ExpiresAt: token.CreatedAt.UTC().Add(accessLength).Unix(),
			Id:        token.ID,
			IssuedAt:  token.CreatedAt.UTC().Unix(),
			Issuer:    d.ServiceID,
			NotBefore: token.CreatedAt.UTC().Add(-1 * time.Hour).Unix(),
			Subject:   token.ProfileID,
		},
		Scopes:      token.Scopes,
		CreatedFrom: token.CreatedFrom,
	})
	fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
	if err != nil {
		return "", err
	}
	t.Header["kid"] = fp
	return t.SignedString(d.JWTPrivateKey)
}

func (d Dependencies) Validate(ctx context.Context, jwtVal string) (AccessToken, error) {
	tok, err := jwt.ParseWithClaims(jwtVal, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
		if err != nil {
			return nil, err
		}
		if fp != token.Header["kid"] {
			return nil, errors.New("unknown signing key")
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
	return AccessToken{
		ID:          claims.Id,
		CreatedFrom: claims.Issuer,
		ProfileID:   claims.Subject,
		ClientID:    claims.Audience,
		Scopes:      claims.Scopes,
		CreatedAt:   time.Unix(claims.IssuedAt, 0),
	}, nil
}

func (d Dependencies) TokenFromRequest(r *http.Request) (*AccessToken, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, ErrInvalidToken
	}
	auth = strings.TrimPrefix(auth, "Bearer ")
	tok, err := d.Validate(r.Context(), auth)
	return &tok, err
}

func InContext(ctx context.Context, token *AccessToken) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}

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
