package main

import (
	"context"
	"log"
	"time"

	rbac "github.com/amupxm/xmus-RBAC"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	cli, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		panic(err)
	}
	mgodb := cli.Database("sampledb")

	roleController := rbac.New(&rbac.Options{Verbose: true, LogManager: log.Println, DbCollection: mgodb.Collection("users")})
	err = roleController.CreateRole(context.Background(), "amir")
	if err != nil {
		log.Println(err)
	}
	err = roleController.DeleteRole(context.Background(), "amir2")
	if err != nil {
		log.Println(err)
	}
}
