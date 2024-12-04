package certification

import (
	"context"
	"encoding/json"

	"github.com/stephnangue/paperclick/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

type CertificationStorer struct {
	collection *mongo.Collection
}

func New(collection *mongo.Collection) CertificationStorer {
	return CertificationStorer{collection: collection}
}

func (c CertificationStorer) Get(code string) ([]models.Certification, error) {
	var certification models.Certification
	filter := bson.M{"code": code}
	err := c.collection.FindOne(context.TODO(), filter).Decode(&certification)
	if err != nil {
		return nil, err
	}

	var certifications []models.Certification
	certifications = append(certifications, certification)

	return certifications, nil
}

func (c CertificationStorer) Create(certi models.Certification) (string, error) {
	result, err := c.collection.InsertOne(context.TODO(), certi)
	if err != nil {
		return "", err
	}
	id, err1 := json.Marshal(result)
	if err1 != nil {
		return "", err1
	}

	return string(id), err
}

func (c CertificationStorer) GetExams(certificationCode string) ([]models.Exam, error) {
	var certification models.Certification
	filter := bson.M{"code": certificationCode}
	err := c.collection.FindOne(context.TODO(), filter).Decode(&certification)
	if err != nil {
		return nil, err
	}
	return certification.Exams, nil
}

func (c CertificationStorer) GetExam(examId string) ([]models.Exam, error) {
	var certification models.Certification
	idObject, err1 := primitive.ObjectIDFromHex(examId)
	if err1 != nil {
		panic(err1)
	}
	filter := bson.M{"exams._id": idObject}
	err := c.collection.FindOne(context.TODO(), filter).Decode(&certification)
	if err != nil {
		return nil, err
	}
	var exams []models.Exam
	for _, v := range certification.Exams {
		if v.ID == idObject {
			exams = append(exams, v)
			break
		}
	}
	return exams, nil
}

func (c CertificationStorer) CreateExams(certificationCode string, exams []models.Exam) (string, error) {
	var examsWithID []models.Exam
	for _, v := range exams {
		v.ID = primitive.NewObjectID()
		examsWithID = append(examsWithID, v)
	}
	filter := bson.M{"code": certificationCode}
	update := bson.M{"$push": bson.M{"exams": bson.M{"$each": examsWithID}}}
	result, err := c.collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return "", err
	}
	createResult, err2 := json.Marshal(result)
	if err2 != nil {
		return "", err2
	}

	return string(createResult), err
}
