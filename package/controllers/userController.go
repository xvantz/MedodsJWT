package controllers

import (
	"context"
	"log"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"BackendMedods/package/database"

	"BackendMedods/package/database/models"
	helper "BackendMedods/package/helpers"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

//HashPassword is used to encrypt the password before it is stored in the DB
func HashPassword(password string) string {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    if err != nil {
        log.Panic(err)
    }

    return string(bytes)
}

//VerifyPassword checks the input password while verifying it with the passward in the DB.
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
    err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
    check := true
    msg := ""

    if err != nil {
        msg = "login or password is incorrect"
        check = false
    }

    return check, msg
}
//CreateUser is the api used to tget a single user
func SignUp() gin.HandlerFunc {
    return func(c *gin.Context) {
        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        var user models.User

        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        validationErr := validate.Struct(user)
        if validationErr != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
            return
        }

        count, err := userCollection.CountDocuments(ctx, bson.M{"Username": user.Username})
        defer cancel()
        if err != nil {
            log.Panic(err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the username"})
            return
        }

        if count > 0 {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "this Username already exists"})
            return
        }
        password := HashPassword(*user.Password)
        user.Password = &password

        user.ID = primitive.NewObjectID()
        _, refreshToken, _ := helper.GenerateAllTokens(*&user.Username)
        user.Refresh_token = &refreshToken

        resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
        if insertErr != nil {
            msg := "User item was not created"
            c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
            return
        }
        defer cancel()

        c.JSON(http.StatusOK, resultInsertionNumber)

    }
}

//Login is the api used to tget a single user
func Login() gin.HandlerFunc {
    return func(c *gin.Context) {
        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        var user models.User
        var foundUser models.User

        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        err := userCollection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&foundUser)
        defer cancel()
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Username incorrect"})
            return
        }

        token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Username)
        c.SetCookie("AccessToken", token, 15415615651, "/", "localhost", false, true)
	    c.SetCookie("RefreshToken", refreshToken, 15415615651, "/", "localhost", false, true)
        helper.UpdateAllTokens(token, refreshToken, foundUser.Username)
        c.JSON(http.StatusOK, token)

    }
}

func RefreshToken() gin.HandlerFunc {
    return func(c *gin.Context) {
        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        var foundUser models.User
        message := "could not refresh access token"
	    cookieRefreshToken, err := c.Cookie("RefreshToken")

	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": message})
	}

	claims, msg := helper.ValidateToken(cookieRefreshToken)
        if msg != "" {
            c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
            c.Abort()
        }
    err = userCollection.FindOne(ctx, bson.M{"username": claims.Username, "refresh_token": cookieRefreshToken}).Decode(&foundUser)
        defer cancel()
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "the user belonging to this token no logger exists"})
            return
        }

    token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Username)
    c.SetCookie("AccessToken", token, 15415615651, "/", "localhost", false, true)
	c.SetCookie("RefreshToken", refreshToken, 15415615651, "/", "localhost", false, true)
    helper.UpdateAllTokens(token, refreshToken, foundUser.Username)
	c.JSON(http.StatusOK, token)
}
}