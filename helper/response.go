package helper

import (
	"encoding/json"
	"net/http"
)

func ResponseJson(w http.ResponseWriter, statusCode int, payload interface{})  {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(response)
}

func ResponseError(w http.ResponseWriter, statusCode int, message string)  {
	ResponseJson(w, statusCode, map[string]string{"message": message})
}