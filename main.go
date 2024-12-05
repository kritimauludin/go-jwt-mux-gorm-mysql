package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/controllers/authcontroller"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/controllers/productcontroller"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/middlewares"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/models"
)

func main()  {
	models.ConnectDatabase()
	routes := mux.NewRouter()

	routes.HandleFunc("/login", authcontroller.Login).Methods("POST")
	routes.HandleFunc("/register", authcontroller.Register).Methods("POST")
	routes.HandleFunc("/logout", authcontroller.Logout).Methods("GET")

	api := routes.PathPrefix("/api").Subrouter()
		api.HandleFunc("/v1/products", productcontroller.Index).Methods("GET")
		api.HandleFunc("/v1/product/{id}", productcontroller.Show).Methods("GET")
		api.HandleFunc("/v1/product", productcontroller.Create).Methods("POST")
		api.HandleFunc("/v1/product/{id}", productcontroller.Update).Methods("PUT")
		api.HandleFunc("/v1/product", productcontroller.Delete).Methods("DELETE")
	api.Use(middlewares.JWTMiddleware)

	log.Fatal(http.ListenAndServe(":8080", routes))
}