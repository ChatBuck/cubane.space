package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Message struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Content   string `json:"content"`
}

type ChatRoom struct {
	Messages []Message
}

var chatRooms = make(map[string]*ChatRoom)

func SendMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roomID := vars["roomID"]
	decoder := json.NewDecoder(r.Body)
	var message Message
	err := decoder.Decode(&message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if chatRooms[roomID] == nil {
		chatRooms[roomID] = &ChatRoom{}
	}
	chatRooms[roomID].Messages = append(chatRooms[roomID].Messages, message)
	w.WriteHeader(http.StatusCreated)
}

func GetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roomID := vars["roomID"]
	if chatRooms[roomID] == nil {
		http.NotFound(w, r)
		return
	}
	messages := chatRooms[roomID].Messages
	json.NewEncoder(w).Encode(messages)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/rooms/{roomID}/messages", SendMessage).Methods("POST")
	r.HandleFunc("/rooms/{roomID}/messages", GetMessages).Methods("GET")
	log.Fatal(http.ListenAndServe(":8081", r))
}
