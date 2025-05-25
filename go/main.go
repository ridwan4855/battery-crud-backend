package main

import (
	"os"

	"github.com/joho/godotenv"

	// "encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	batteries   []Battery
	batteryLock sync.Mutex
	jwtSecret   []byte
)

type Battery struct {
	ID       string  `json:"id"`
	Name     string  `json:"name" binding:"required"`
	Type     string  `json:"type" binding:"required"`
	Voltage  float64 `json:"voltage" binding:"required,gt=0"`
	Capacity int     `json:"capacity" binding:"required,gt=0"`
	Price    float64 `json:"price" binding:"required,gt=0"`
}

type UserCredentials struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func main() {
	// Load .env file
	_ = godotenv.Load(".env.local")

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
        panic("JWT_SECRET environment variable not set")
    }

	fmt.Println("✅ Environment loaded successfully")

	r := gin.Default()

	// CORS Middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Auth Routes
	r.POST("/login", loginHandler)
	
	// Protected Routes
	auth := r.Group("/")
	auth.Use(authMiddleware)
	{
		auth.GET("/batteries", getBatteries)
		auth.POST("/batteries", createBattery)
		auth.PUT("/batteries/:id", updateBattery)
		auth.DELETE("/batteries/:id", deleteBattery)
	}

	port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    r.Run(":" + port) 
}

// Authentication Handlers
func loginHandler(c *gin.Context) {
	var creds UserCredentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simple authentication
	valid := creds.Username == "admin" && creds.Password == "password"
    if !valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }
	
	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": creds.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Battery CRUD Handlers
func getBatteries(c *gin.Context) {
	batteryLock.Lock()
	defer batteryLock.Unlock()
	c.JSON(http.StatusOK, batteries)
}

func createBattery(c *gin.Context) {
	var newBattery Battery
	if err := c.ShouldBindJSON(&newBattery); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	batteryLock.Lock()
	defer batteryLock.Unlock()

	newBattery.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	batteries = append(batteries, newBattery)
	c.JSON(http.StatusCreated, newBattery)
}

func updateBattery(c *gin.Context) {
	id := c.Param("id")
	var updatedBattery Battery
	
	if err := c.ShouldBindJSON(&updatedBattery); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	batteryLock.Lock()
	defer batteryLock.Unlock()

	for i, b := range batteries {
		if b.ID == id {
			updatedBattery.ID = id
			batteries[i] = updatedBattery
			c.JSON(http.StatusOK, updatedBattery)
			return
		}
	}
	
	c.JSON(http.StatusNotFound, gin.H{"error": "Battery not found"})
}

func deleteBattery(c *gin.Context) {
	id := c.Param("id")
	
	batteryLock.Lock()
	defer batteryLock.Unlock()

	for i, b := range batteries {
		if b.ID == id {
			batteries = append(batteries[:i], batteries[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Battery deleted"})
			return
		}
	}
	
	c.JSON(http.StatusNotFound, gin.H{"error": "Battery not found"})
}

// Middleware
func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
	  c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
	  return
	}
  
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	  if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	  }
	  return jwtSecret, nil
	})
  
	if err != nil || !token.Valid {
	  c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
	  return
	}
  
	c.Next()
  }