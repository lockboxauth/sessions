package sessions

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"impractical.co/pqarrays"
	yall "yall.in"
)

const (
	accessLength = 1 * time.Hour
)

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
)

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
	JWTSecret string
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
	}).SignedString([]byte(d.JWTSecret))
}

func (d Dependencies) Validate(ctx context.Context, jwtVal string) (AccessToken, error) {
	tok, err := jwt.ParseWithClaims(jwtVal, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(d.JWTSecret), nil
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
