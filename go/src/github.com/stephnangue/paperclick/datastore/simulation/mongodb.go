package simulation

import (
	"context"
	"encoding/json"

	"github.com/stephnangue/paperclick/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

type SimulationStorer struct {
	collection *mongo.Collection
}

func New(collection *mongo.Collection) SimulationStorer {
	return SimulationStorer{collection: collection}
}

func (s SimulationStorer) GetExamSimulations(examId string) ([]models.Simulation, error) {
	idObject, err1 := primitive.ObjectIDFromHex(examId)
	if err1 != nil {
		return nil, err1
	}
	filter := bson.M{"examId": idObject}
	cursor, err := s.collection.Find(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	var simulations []models.Simulation
	for cursor.Next(context.TODO()) {
		var simulation models.Simulation
		if err := cursor.Decode(&simulation); err != nil {
			return nil, err
		}
		simulations = append(simulations, simulation)
	}

	return simulations, nil
}

func (s SimulationStorer) Get(simulationId string) ([]models.Simulation, error) {
	idObject, err1 := primitive.ObjectIDFromHex(simulationId)
	if err1 != nil {
		return nil, err1
	}
	filter := bson.M{"_id": idObject}
	cursor, err := s.collection.Find(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	var simulations []models.Simulation
	for cursor.Next(context.TODO()) {
		var simulation models.Simulation
		if err := cursor.Decode(&simulation); err != nil {
			return nil, err
		}
		simulations = append(simulations, simulation)
	}

	return simulations, nil
}

func (s SimulationStorer) Create(examId string, simulation models.Simulation) (string, error) {
	examID, err1 := primitive.ObjectIDFromHex(examId)
	if err1 != nil {
		return "", err1
	}
	simulation.ExamID = examID

	result, err := s.collection.InsertOne(context.TODO(), simulation)
	if err != nil {
		return "", err
	}
	resultJson, err2 := json.Marshal(result)
	if err2 != nil {
		return "", err2
	}

	return string(resultJson), nil
}

func (s SimulationStorer) Update(simulationId string, simulation models.Simulation) (string, error) {
	idObject, err1 := primitive.ObjectIDFromHex(simulationId)
	if err1 != nil {
		panic(err1)
	}
	filter := bson.M{"_id": idObject}
	update := bson.M{"$set": simulation}

	result, err := s.collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return "", err
	}
	resultJson, err2 := json.Marshal(result)
	if err2 != nil {
		return "", err2
	}

	return string(resultJson), nil
}
