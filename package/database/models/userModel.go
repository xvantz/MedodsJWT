package models

import (
    "go.mongodb.org/mongo-driver/bson/primitive"
)

//User is the model that governs all notes objects retrived or inserted into the DB
type User struct {
    ID            primitive.ObjectID `bson:"_id"`
	Username      string             `json:"Username" validate:"required,min=6"`
    Password      *string            `json:"Password" validate:"required,min=6"`
    Refresh_token *string            `json:"refresh_token"`

}