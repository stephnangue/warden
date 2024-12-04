package driver

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/mgo.v2/bson"
)

func GetCollection(dbName string, collectionName string) (*mongo.Collection, error) {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}

	collection := client.Database(dbName).Collection(collectionName)

	// Create an index on certifications
	if collectionName == "certifications" {
		_, err := collection.Indexes().CreateOne(
			context.TODO(),
			mongo.IndexModel{
				Keys:    bson.M{"code": 1},
				Options: options.Index().SetUnique(true),
			},
		)
		if err != nil {
			return nil, err
		}
	}

	return collection, nil
}
