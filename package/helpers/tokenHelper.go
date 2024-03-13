package helper

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"time"

	"BackendMedods/package/database"

	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// SignedDetails
type SignedDetails struct {
    Username      string
    jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

// GenerateAllTokens generates both teh detailed token and refresh token
func GenerateAllTokens(username string) (signedToken string, signedRefreshToken string, err error) {
    var base64EncodeRefreshToken string
    claims := &SignedDetails{
        Username:      username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
        },
    }
    refreshClaims := &SignedDetails{
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
        },
    }

    token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
        log.Panic(err)
        return
    }

    refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
    base64EncodeRefreshToken = base64.StdEncoding.EncodeToString([]byte(refreshToken))
    if err != nil {
        log.Panic(err)
        return
    }

    return token, base64EncodeRefreshToken, err
}

//ValidateToken validates the jwt token
func ValidateToken(RefreshToken string) (claims *SignedDetails, msg string) {
    var base64DecodeRefreshToken, err = base64.StdEncoding.DecodeString(RefreshToken)
    token, err := jwt.ParseWithClaims(
        string(base64DecodeRefreshToken),
        &SignedDetails{},
        func(token *jwt.Token) (interface{}, error) {
            return []byte(SECRET_KEY), nil
        },
    )

    if err != nil {
        msg = err.Error()
        return
    }

    claims, ok := token.Claims.(*SignedDetails)
    if !ok {
        msg = "the token is invalid"
        msg = err.Error()
        return
    }

    if claims.ExpiresAt < time.Now().Local().Unix() {
        msg = "token is expired"
        msg = err.Error()
        return
    }

    return claims, msg
}

//UpdateAllTokens renews the user tokens when they login
func UpdateAllTokens(signedToken string, signedRefreshToken string, username string) {
    var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
    var bcryptRefreshToken, error = bcrypt.GenerateFromPassword([]byte(signedRefreshToken), 14)
    if error != nil {
        log.Panic(error)
        return
    }
    var updateObj primitive.D
    updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: bcryptRefreshToken})

    upsert := true
    filter := bson.M{"username": username}
    opt := options.UpdateOptions{
        Upsert: &upsert,
    }

    _, err := userCollection.UpdateOne(
        ctx,
        filter,
        bson.D{
            {Key: "$set", Value: updateObj},
        },
        &opt,
    )
    defer cancel()

    if err != nil {
        log.Panic(err)
        return
    }
}
