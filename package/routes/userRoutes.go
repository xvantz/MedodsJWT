package routes

import (
    controller "BackendMedods/package/controllers"

    "github.com/gin-gonic/gin"
)

//UserRoutes function
func UserRoutes(incomingRoutes *gin.Engine) {
    incomingRoutes.POST("/users/signup", controller.SignUp())
    incomingRoutes.POST("/users/login", controller.Login())
    incomingRoutes.POST("/users/refreshtoken", controller.RefreshToken())
}