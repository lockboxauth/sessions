package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/apex/log"
	jwt "github.com/dgrijalva/jwt-go"
	"impractical.co/pqarrays"
)

const (
	accessLength = 1 * time.Hour
)

var ErrInvalidToken = errors.New("invalid token")

type AccessToken struct {
	ID          string
	CreatedFrom string
	Scopes      pqarrays.StringArray
	ProfileID   string
	ClientID    string
	CreatedAt   time.Time
}

type AccessTokenClaims struct {
	jwt.StandardClaims
	Scopes []string
}

type Dependencies struct {
	JWTPrivateKey string
	JWTPublicKey  string
	Log           *log.Logger
}

func (d Dependencies) CreateJWT(ctx context.Context, token AccessToken) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, AccessTokenClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  token.ClientID,
			ExpiresAt: token.CreatedAt.UTC().Add(accessLength).Unix(),
			Id:        token.ID,
			IssuedAt:  token.CreatedAt.UTC().Unix(),
			Issuer:    token.CreatedFrom,
			NotBefore: token.CreatedAt.UTC().Add(-1 * time.Hour).Unix(),
			Subject:   token.ProfileID,
		},
		Scopes: token.Scopes,
	}).SignedString(d.JWTPrivateKey)
}

func (d Dependencies) Validate(ctx context.Context, jwtVal string) (AccessToken, error) {
	tok, err := jwt.Parse(jwtVal, func(token *jwt.Token) (interface{}, error) {
		return d.JWTPublicKey, nil
	})
	if err != nil {
		d.Log.WithError(err).Debug("Error validating token.")
		return AccessToken{}, ErrInvalidToken
	}
	claims, ok := tok.Claims.(AccessTokenClaims)
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