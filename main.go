package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

type User struct {
	ID                      primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Email                   string             `json:"email,omitempty" bson:"email,omitempty"`
	Username                string             `json:"username" bson:"username,omitempty"`
	Password                string             `json:"password,omitempty" bson:"password,omitempty"`
	Token                   string             `json:"token,omitempty" bson:"token,omitempty"`
	TokenExpirationDateTime primitive.DateTime `json:"token_expiration_date_time,omitempty"`
	Verified                bool               `json:"verified,omitempty" bson:"verified,omitempty"`
}

type Meal struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name        string             `json:"name,omitempty" bson:"name,omitempty"`
	Description string             `json:"description,omitempty" bson:"description,omitempty"`
	Owner       primitive.ObjectID `json:"owner_id,omitempty" bson:"owner_id,omitempty"`
}

type Profile struct {
	User  User   `json:"user" bson:"user"`
	Meals []Meal `json:"meals" bson:"meals"`
}

var client *mongo.Client

func writeResponse(response http.ResponseWriter, header int, msg string) {
	response.WriteHeader(header)
	response.Write([]byte(`{ "message": "` + msg + `" }`))
}

func GenerateVerificationToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func SendVerificationEmail(user *User) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_USER"))
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "Verify your email address")
	m.SetBody("text/plain", "http://127.0.0.1:8000/verify/"+user.Token)

	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	d := gomail.NewDialer(os.Getenv("SMTP_HOST"), port, os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS"))

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func Authenticate(header http.Header, profile *Profile) error {
	tokenString := header.Get("Authorization")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate that the signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		profile.User.ID, _ = primitive.ObjectIDFromHex(claims["id"].(string))
		profile.User.Email = claims["email"].(string)
		profile.User.Username = claims["username"].(string)

		return nil
	}

	return err
}

func FindMeals(filter interface{}) ([]Meal, error) {
	collection := client.Database("foodie").Collection("meal")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	var meals []Meal
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var meal Meal
		err = cursor.Decode(&meal)
		if err != nil {
			return nil, err
		}
		meals = append(meals, meal)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return meals, nil
}

func GetRegisterEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	// Decode the request into a User struct
	var user User
	_ = json.NewDecoder(request.Body).Decode(&user)

	// TODO Check that the username and email are valid

	collection := client.Database("foodie").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	// Check for an exiting entry with the same username
	var existing User
	err := collection.FindOne(ctx, bson.D{primitive.E{Key: "email", Value: user.Email}}).Decode(&existing)
	if err != mongo.ErrNoDocuments {
		// If the email is verified then we need to use a different email address
		if existing.Verified {
			writeResponse(response, http.StatusExpectationFailed, "Email is already registered")
			return
		}
	}
	err = collection.FindOne(ctx, bson.D{primitive.E{Key: "username", Value: user.Username}}).Decode(&existing)
	if err != mongo.ErrNoDocuments {
		// If the username is verified then we need to use a different username
		if existing.Verified {
			writeResponse(response, http.StatusExpectationFailed, "Username is taken")
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, "Error while hashing password, try again. "+err.Error())
		return
	}
	user.Password = string(hash)

	// Generate a verification token
	user.Token = GenerateVerificationToken()

	// TODO And the expiration date is 24 hours from now
	user.TokenExpirationDateTime = primitive.NewDateTimeFromTime(time.Now().AddDate(0, 0, 1))

	// Insert the User into the database with the hashed password
	_, err = collection.UpdateOne(ctx, bson.D{primitive.E{Key: "email", Value: user.Email}}, bson.M{"$set": user}, options.Update().SetUpsert(true))
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, "Error while creating user, try again. "+err.Error())
		return
	}

	// TODO Send a verification email to the user
	err = SendVerificationEmail(&user)
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, "Error while sending verification email, try again"+err.Error())
		return
	}

	writeResponse(response, http.StatusOK, "Verification email sent")
}

func GetVerifyEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	params := mux.Vars(request)
	verificationToken, _ := params["token"]

	collection := client.Database("foodie").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	// Query the database for the user and set the entry to verified
	var existing User
	err := collection.FindOne(ctx, bson.D{primitive.E{Key: "token", Value: verificationToken}}).Decode(&existing)
	if err != nil {
		writeResponse(response, http.StatusExpectationFailed, "Invalid verification token"+err.Error())
		return
	}

	// Set the user to verified
	_, err = collection.UpdateOne(ctx, bson.D{primitive.E{Key: "_id", Value: existing.ID}}, bson.M{"$set": bson.M{"verified": true}})

	writeResponse(response, http.StatusOK, "Verification successful")
}

func GetLoginEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	var user User
	_ = json.NewDecoder(request.Body).Decode(&user)

	collection := client.Database("foodie").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	var existing User
	err := collection.FindOne(ctx, bson.D{primitive.E{Key: "email", Value: user.Email}}).Decode(&existing)

	if err != nil {
		// TODO Handle other errors
		switch err {
		case mongo.ErrNoDocuments:
			writeResponse(response, http.StatusNotAcceptable, "Email is not registered. "+err.Error())
			return
		}
	}

	if !existing.Verified {
		writeResponse(response, http.StatusUnauthorized, "User is not verified")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(user.Password))
	if err != nil {
		writeResponse(response, http.StatusUnauthorized, "Invalid password")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       existing.ID.Hex(),
		"email":    existing.Email,
		"username": existing.Username,
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		writeResponse(response, http.StatusInternalServerError, "Error while generating token, try again"+err.Error())
		return
	}

	json.NewEncoder(response).Encode(tokenString)
}

func GetProfileEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	var profile Profile
	err := Authenticate(request.Header, &profile)
	if err != nil {
		writeResponse(response, http.StatusUnauthorized, err.Error())
		return
	}

	meals, err := FindMeals(bson.D{primitive.E{Key: "owner", Value: profile.User.ID}})
	if err != nil {
		// TODO Handle the error properly, we should indicate why the error occurred
		writeResponse(response, http.StatusInternalServerError, err.Error())
		return
	}

	profile.Meals = meals
	json.NewEncoder(response).Encode(profile)
}

func CreateMealEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	var profile Profile
	err := Authenticate(request.Header, &profile)
	if err != nil {
		writeResponse(response, http.StatusUnauthorized, err.Error())
		return
	}

	var meal Meal
	_ = json.NewDecoder(request.Body).Decode(&meal)
	meal.Owner = profile.User.ID

	collection := client.Database("foodie").Collection("meal")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	result, err := collection.InsertOne(ctx, meal)
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, "Error while creating meal, try again"+err.Error())
		return
	}
	json.NewEncoder(response).Encode(result)
}

func GetMealListEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	collection := client.Database("foodie").Collection("meal")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)

	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, err.Error())
		return
	}

	var meals []Meal
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var meal Meal
		err = cursor.Decode(&meal)
		if err != nil {
			writeResponse(response, http.StatusInternalServerError, err.Error())
			return
		}
		meals = append(meals, meal)
	}

	if err := cursor.Err(); err != nil {
		writeResponse(response, http.StatusInternalServerError, err.Error())
		return
	}

	json.NewEncoder(response).Encode(meals)
}

func GetMealEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")

	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])

	collection := client.Database("foodie").Collection("meal")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)

	var meal Meal
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&meal)
	if err != nil {
		writeResponse(response, http.StatusInternalServerError, err.Error())
		return
	}

	json.NewEncoder(response).Encode(meal)
}

func main() {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	const MONGODB_URI = "mongodb://127.0.0.1:27017"

	clientOptions := options.Client().ApplyURI(MONGODB_URI)
	client, _ = mongo.Connect(ctx, clientOptions)

	// Ensure that we are successfully connected to the database
	err := client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer client.Disconnect(ctx)
	fmt.Println("👌 Successfuly connected to MongoDB at:", MONGODB_URI)

	router := mux.NewRouter()
	router.HandleFunc("/register", GetRegisterEndpoint).Methods("POST")
	router.HandleFunc("/verify/{token}", GetVerifyEndpoint).Methods("GET")
	router.HandleFunc("/login", GetLoginEndpoint).Methods("POST")
	router.HandleFunc("/profile", GetProfileEndpoint).Methods("GET")
	router.HandleFunc("/meals", CreateMealEndpoint).Methods("POST")
	router.HandleFunc("/meals", GetMealListEndpoint).Methods("GET")
	router.HandleFunc("/meals/{id}", GetMealEndpoint).Methods("GET")

	fmt.Println("🚀 Listening at: http://127.0.0.1:8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}
